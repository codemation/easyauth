import asyncio
import datetime
import json
import logging
import os
import random
import string
import subprocess
import uuid
from inspect import Parameter, signature
from typing import Any, Union

import bcrypt
import jwcrypto.jwk as jwk
import python_jwt as jwt
from easyadmin.elements import buttons, modal, scripts
from easyadmin.pages import admin
from easyrpc.server import EasyRpcServer
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.encoders import jsonable_encoder
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.security import OAuth2PasswordBearer
from fastapi_mail import ConnectionConfig, FastMail, MessageSchema
from google.auth.transport import requests
from google.oauth2 import id_token
from makefun import wraps

from easyauth.api import api_setup
from easyauth.db import database_setup
from easyauth.exceptions import (
    GoogleOauthHeaderMalformed,
    GoogleOauthNotEnabledOrConfigured,
)
from easyauth.frontend import frontend_setup
from easyauth.models import (
    Actions,
    EmailConfig,
    Groups,
    OauthConfig,
    PendingUsers,
    Roles,
    Services,
    Tokens,
    Users,
)
from easyauth.pages import (
    ActivationPage,
    ForbiddenPage,
    LoginPage,
    NotFoundPage,
    RegisterPage,
)
from easyauth.router import EasyAuthAPIRouter


class EasyAuthServer:
    def __init__(
        self,
        server: FastAPI,
        token_url: str,
        rpc_server: EasyRpcServer,
        admin_title: str = "EasyAuth",
        admin_prefix: str = "/admin",
        logger: logging.Logger = None,
        manager_proxy_port: int = 8092,
        debug: bool = False,
        env_from_file: str = None,
        default_permission: dict = {"groups": ["administrators"]},
        secure: bool = False,
        private_key: str = None,
    ):
        self.server = server
        self.server.title = admin_title
        self.ADMIN_PREFIX = admin_prefix
        self.oauth2_scheme = OAuth2PasswordBearer(tokenUrl=token_url)  # /token
        self.DEFAULT_PERMISSION = default_permission

        self.rpc_server = rpc_server

        # cookie security
        self.cookie_security = {
            "secure": secure,
            "samesite": "lax" if not secure else "none",
        }

        # logging setup #
        self.log = logger
        self.debug = debug
        level = None if not self.debug else "DEBUG"
        self.setup_logger(logger=self.log, level=level)

        # extra routers
        self.api_routers = []

        EasyAuthAPIRouter.parent = self
        for page in {
            LoginPage,
            RegisterPage,
            ActivationPage,
            NotFoundPage,
            ForbiddenPage,
        }:
            page.parent = self

        if env_from_file:
            self.load_env_from_file(env_from_file)

        # env variable checks #
        assert "ISSUER" in os.environ, f"missing ISSUER env variable"
        assert "SUBJECT" in os.environ, f"missing SUBJECT env variable"
        assert "AUDIENCE" in os.environ, f"missing AUDIENCE env variable"

        # setup keys
        if not private_key:
            self.key_setup()
        else:
            self._privkey = jwk.JWK.from_json(private_key)

        # setup allowed origins - where can server receive token requests from
        self.cors_setup()

        @server.on_event("startup")
        async def setup():
            self.log.warning("adding routers")
            await self.include_routers()

        @server.on_event("shutdown")
        async def shutdown_auth_server():
            self.log.warning("EasyAuthServer - Starting shutdown process!")
            if self.leader:
                shutdown_proxies = f"for pid in $(ps aux | grep {manager_proxy_port}' | awk '{{print $2}}'); do kill $pid; done"
                os.system(shutdown_proxies)
            self.log.warning("EasyAuthServer - Finished shutdown process!")

        @NotFoundPage.mark()
        def default_not_found_page():
            return HTMLResponse(self.admin.not_found_page(), status_code=404)

        @server.middleware("http")
        async def detect_token_in_cookie(request, call_next):
            request_dict = dict(request)
            request_header = dict(request.headers)
            token_in_cookie = None
            auth_ind = None
            cookie_ind = None

            for i, header in enumerate(request_dict["headers"]):
                if "authorization" in header[0].decode() and header[1] is not None:
                    auth_ind = i
                if "cookie" in header[0].decode():
                    cookie_ind = i
                    cookies = header[1].decode().split(",")
                    for cookie in cookies[0].split("; "):
                        key, value = cookie.split("=")
                        if key == "token":
                            token_in_cookie = value
            if token_in_cookie and token_in_cookie != "INVALID":
                if auth_ind:
                    request.headers.__dict__["_list"].pop(auth_ind)
                if request_dict["path"] != "/login":
                    request.headers.__dict__["_list"].append(
                        ("authorization".encode(), f"bearer {token_in_cookie}".encode())
                    )
                else:
                    return RedirectResponse("/logout")
            elif request_dict["path"] != "/login":
                token_in_cookie = "NO_TOKEN" if not token_in_cookie else token_in_cookie
                request_dict["headers"].append(
                    ("authorization".encode(), f"bearer {token_in_cookie}".encode())
                )

            return await call_next(request)

        @server.middleware("http")
        async def handle_401_403(request, call_next):
            response = await call_next(request)
            request_dict = dict(request)

            if response.status_code in [401, 404]:
                if "text/html" in request.headers["accept"]:
                    if response.status_code == 404:
                        return self.html_not_found_page()

                    response = HTMLResponse(
                        await self.get_login_page(
                            message="Login Required", request=request
                        ),
                        status_code=401,
                    )
                    response.set_cookie("token", "INVALID", **self.cookie_security)
                    response.set_cookie(
                        "ref", request.__dict__["scope"]["path"], **self.cookie_security
                    )

            if response.status_code == 500:
                self.log.error(
                    f"Internal error - 500 - with request: {request.__dict__}"
                )
            return response

        @self.rpc_server.origin(namespace="admin")
        async def login_stuff():
            pass

    @classmethod
    async def create(
        cls,
        server: FastAPI,
        token_url: str,
        auth_secret: str,
        admin_title: str = "EasyAuth",
        admin_prefix: str = "/admin",
        logger: logging.Logger = None,
        manager_proxy_port: int = 8092,
        debug: bool = False,
        env_from_file: str = None,
        default_permission: dict = {"groups": ["administrators"]},
        secure: bool = False,
        private_key: str = None,
    ):

        rpc_server = EasyRpcServer(server, "/ws/easyauth", server_secret=auth_secret)

        auth_server = cls(
            server,
            token_url,
            rpc_server,
            admin_title,
            admin_prefix,
            logger,
            manager_proxy_port,
            debug,
            env_from_file,
            default_permission,
            secure,
            private_key,
        )

        await database_setup(auth_server)
        await api_setup(auth_server)
        await frontend_setup(auth_server)

        if auth_server.leader:

            # create subprocess for manager proxy
            auth_server.log.warning(f"starting manager_proxy")
            auth_server.manager_proxy = subprocess.Popen(
                f"gunicorn easyauth.manager_proxy:server -w 1 -k uvicorn.workers.UvicornWorker -b 127.0.0.1:8092".split(
                    " "
                )
            )
            auth_server.log.warning(f"leader - waiting for members to start")
            await asyncio.sleep(5)
        else:
            auth_server.log.warning(
                f"member - db setup complete - starting manager proxies"
            )
            await asyncio.sleep(5)

        async def client_update(action: str, store: str, key: str, value: Any):
            """
            update every connected client
            """
            clients = auth_server.rpc_server["global_store"]
            for client in clients:
                if client == "get_store_data":
                    continue
                await clients[client](action, store, key, value)
            return f"client_update completed"

        async def token_cleanup():
            return await auth_server.token_cleanup()

        client_id = "_".join(str(uuid.uuid4()).split("-"))

        client_update.__name__ = client_update.__name__ + client_id
        token_cleanup.__name__ = token_cleanup.__name__ + client_id

        # initialize global storage
        auth_server.store = {"tokens": {}}

        async def store_data(action: str, store: str, key: str, value: Any = None):
            """
            actions:
                - put|update|delete
            """
            if store not in auth_server.store:
                auth_server.store[store] = {}
            if action in {"update", "put"}:
                auth_server.store[store][key] = value
            else:
                if key in auth_server.store[store]:
                    del auth_server.store[store][key]

            return f"{action} in {store} with {key} completed"

        store_data.__name__ = store_data.__name__ + client_id

        rpc_server.origin(store_data, namespace="global_store")

        @rpc_server.origin(namespace="global_store")
        async def get_store_data():
            rpc_server.get_all_registered_functions(namespace="global_store")
            return auth_server.store

        # register unique client_update in clients namespace
        rpc_server.origin(client_update, namespace="clients")
        rpc_server.origin(token_cleanup, namespace="clients")

        # create connection to manager on 'manager' and 'clients' namespace
        await rpc_server.create_server_proxy(
            "127.0.0.1",
            manager_proxy_port,
            "/ws/manager",
            server_secret=os.environ["RPC_SECRET"],
            namespace="clients",
        )

        await rpc_server.create_server_proxy(
            "127.0.0.1",
            manager_proxy_port,
            "/ws/manager",
            server_secret=os.environ["RPC_SECRET"],
            namespace="manager",
        )

        @rpc_server.origin(namespace="easyauth")
        async def get_setup_info():
            return {
                "token_url": token_url,
                "public_rsa": auth_server._privkey.export_public(),
            }

        @rpc_server.origin(namespace="easyauth")
        async def get_identity_providers():
            return await auth_server.get_identity_providers()

        @rpc_server.origin(namespace="easyauth")
        async def generate_google_oauth_token(auth_code):
            return await auth_server.generate_google_oauth_token(auth_code=auth_code)

        if auth_server.leader:
            await asyncio.sleep(1)
            valid_tokens = await Tokens.all()
            for token in valid_tokens:
                await auth_server.global_store_update(
                    "update", "tokens", token.token_id, ""
                )
        else:
            await asyncio.sleep(3)

        auth_server.log.warning(
            f"EasyAuthServer Started! - Loaded Tokens {auth_server.store['tokens']}"
        )

        return auth_server

    def load_env_from_file(self, file_path):
        self.log.warning(f"loading env vars from {file_path}")
        with open(file_path, "r") as json_env:
            env_file = json.load(json_env)
            for env, value in env_file.items():
                os.environ[env] = value

    def setup_logger(self, logger=None, level=None):
        if logger is None:
            level = logging.DEBUG if level == "DEBUG" else logging.WARNING
            logging.basicConfig(
                level=level,
                format="%(asctime)s %(name)-12s %(levelname)-8s %(message)s",
                datefmt="%m-%d %H:%M",
            )
            self.log = logging.getLogger("EasyAuthServer")
            self.log.propogate = False
            self.log.setLevel(level)
        else:
            self.log = logger

    def key_setup(self):
        # check if keys exist in KEY_PATH else create
        assert "KEY_PATH" in os.environ, f"missing KEY_PATH env variable"
        assert "KEY_NAME" in os.environ, f"missing KEY_NAME env variable"

        try:
            with open(
                f"{os.environ['KEY_PATH']}/{os.environ['KEY_NAME']}.key", "r"
            ) as k:
                self._privkey = jwk.JWK.from_json(k.readline())
        except Exception:
            # create private / public keys
            self._privkey = jwk.JWK.generate(
                kid=self.generate_random_string(56), kty="RSA", size=2048
            )
            with open(
                f"{os.environ['KEY_PATH']}/{os.environ['KEY_NAME']}.key", "w"
            ) as k:
                k.write(self._privkey.export_private())
        try:
            with open(
                f"{os.environ['KEY_PATH']}/{os.environ['KEY_NAME']}.pub", "r"
            ) as k:
                pass
        except Exception:
            with open(
                f"{os.environ['KEY_PATH']}/{os.environ['KEY_NAME']}.pub", "w"
            ) as pb:
                pb.write(self._privkey.export_public())

    async def include_routers(self):
        for auth_api_router in self.api_routers:
            self.server.include_router(auth_api_router.server)

    def create_api_router(self, *args, **kwargs):
        api_router = EasyAuthAPIRouter.create(*args, **kwargs)
        self.api_routers.append(api_router)
        return api_router

    async def get_403_page(self):
        body = """
            <div class="text-center">
                <div class="error mx-auto" data-text="Forbidden">Forbidden</div>
                <p class="text-gray-500 mb-0">You dont have permission to view this</p>
                <a href="/login">&larr; Back to Login</a>
            </div>
        """
        logout_modal = modal.get_modal(
            "logoutModal",
            alert="Ready to Leave",
            body=buttons.get_button(
                "Go Back", color="success", href=f"{self.ADMIN_PREFIX}/"
            )
            + scripts.get_google_signout_script()
            + buttons.get_button("Log out", color="danger", onclick="signOut()"),
            footer="",
            size="sm",
        )

        return (
            admin.get_admin_page(
                name="",
                sidebar=self.admin.sidebar,
                body="",
                topbar_extra=body,
                current_user="",
                modals=logout_modal,
                google=await self.get_google_oauth_client_id(),
            )
            if not hasattr(self, "html_forbidden_page")
            else self.html_forbidden_page()
        )

    async def get_login_page(self, message, request: Request = None, **kwargs):
        redirect_ref = f"{self.ADMIN_PREFIX}"
        if request and "ref" in request.cookies:
            redirect_ref = request.cookies["ref"]

        identity_providers = await self.get_identity_providers()

        return (
            self.admin.login_page(
                welcome_message=message,
                login_action="/login",
                **identity_providers,
                google_redirect_url=redirect_ref,
            )
            if not hasattr(self, "html_login_page")
            else self.html_login_page()
        )

    async def email_setup(
        self,
        username: str,
        password: str,
        mail_from: str,
        mail_from_name: str,
        server: str,
        port: int,
        mail_tls: bool,
        mail_ssl: bool,
        send_activation_emails: bool,
    ):

        # clear existing email config
        for email_config in await EmailConfig.all():
            await email_config.delete()

        # encode password
        encoded_password = self.encode(days=99000, password=password)

        await EmailConfig.create(
            username=username,
            password=encoded_password,
            mail_from=mail_from,
            mail_from_name=mail_from_name,
            server=server,
            port=port,
            mail_tls=mail_tls,
            mail_ssl=mail_ssl,
            is_enabled=False,
            send_activation_emails=send_activation_emails,
        )

        return "email setup completed"

    async def get_email_config(self) -> EmailConfig:
        return await EmailConfig.all()

    async def send_email(
        self, subject: str, email: str, recipients, test_email: bool = False
    ):

        conf = await self.get_email_config()
        if not conf:
            return f"no email server configured"

        decoded = self.decode(conf[0]["password"])

        conf[0]["password"] = decoded[1]["password"]
        conf = conf[0]

        conf = ConnectionConfig(
            **{
                "MAIL_USERNAME": conf["username"],
                "MAIL_PASSWORD": conf["password"],
                "MAIL_FROM": conf["mail_from"],
                "MAIL_PORT": conf["port"],
                "MAIL_SERVER": conf["server"],
                "MAIL_FROM_NAME": conf["mail_from_name"],
                "MAIL_TLS": conf["mail_tls"],
                "MAIL_SSL": conf["mail_ssl"],
            }
        )

        body = f"""<p>{email}</p>"""

        message = MessageSchema(
            subject=f"{subject}",
            recipients=recipients
            if isinstance(recipients, list)
            else [recipients],  # List of recipients, as many as you can pass
            body=body,
            subtype="html",
        )

        async def email_send():
            try:
                return await fm.send_message(message)
            except Exception as e:
                self.log.exception("Error sending email")
                return f"Error Sending Email - {repr(e)}"

        fm = FastMail(conf)
        if not test_email:
            asyncio.create_task(email_send())
        else:
            result = await email_send()
        return {"message": "email sent"}

    def cors_setup(self):
        origins = ["*"]

        self.server.add_middleware(
            CORSMiddleware,
            allow_origins=origins,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    async def global_store_update(self, action, store, key, value):
        manager_methods = self.rpc_server["manager"]
        if "global_store_update" in manager_methods:
            await manager_methods["global_store_update"](action, store, key, value)
        return

    async def revoke_token(self, token_id: str):
        token = await Tokens.get(token_id=token_id)
        if token:
            await token.delete()
        await self.global_store_update("delete", "tokens", key=token_id, value="")

    async def token_cleanup(self):
        """
        check & delete expired tokens
        """
        all_tokens = await Tokens.all()
        revoked_tokens = [
            {token.token_id: asyncio.create_task(self.revoke_token(token.token_id))}
            for token in all_tokens
            if datetime.datetime.now()
            > datetime.datetime.fromisoformat(token.expiration)
        ]

        self.log.warning(f"token_cleanup cleared {len(revoked_tokens)} expired tokens")
        return f"finished cleaning {len(revoked_tokens)} expired tokens"

    async def issue_token(self, permissions, minutes=60, hours=0, days=0):

        token_id = str(uuid.uuid4())

        payload = {
            "iss": os.environ["ISSUER"],
            "sub": os.environ["SUBJECT"],
            "aud": os.environ["AUDIENCE"],
            "token_id": token_id,
            "permissions": permissions,
        }

        expiration = datetime.datetime.now() + datetime.timedelta(
            minutes=minutes, hours=hours, days=days
        )

        await Tokens.create(
            token_id=token_id,
            username=permissions["users"][0],
            issued=datetime.datetime.now().isoformat(),
            expiration=expiration.isoformat(),
            token=permissions,
        )

        token = jwt.generate_jwt(
            payload,
            self._privkey,
            "RS256",
            datetime.timedelta(minutes=minutes, hours=hours, days=days),
        )

        # this should be done once issue token context exits
        # since this can be triggered by a client, which could not
        # correctly update its token id store while waiting on the issue_token response
        asyncio.create_task(
            self.global_store_update("update", "tokens", key=token_id, value="")
        )

        return token

    def decode_token(self, token):
        # with open(f"{os.environ['KEY_PATH']}/{os.environ['KEY_NAME']}.pub", 'r') as pb_key:
        return jwt.verify_jwt(token, self._privkey, ["RS256"])

    def encode(self, minutes=60, days=0, **kw):
        return jwt.generate_jwt(
            kw, self._privkey, "RS256", datetime.timedelta(minutes=minutes, days=days)
        )

    def decode(self, encoded):
        return jwt.verify_jwt(encoded, self._privkey, ["RS256"])

    def generate_random_string(self, size: int) -> str:
        letters = string.ascii_lowercase
        return "".join(random.choice(letters) for i in range(size))

    def encode_password(self, pw):
        hash_and_salt = bcrypt.hashpw(pw.encode(), bcrypt.gensalt())
        return hash_and_salt.decode()

    def is_password_valid(self, encoded, input_password):
        has_and_salt = encoded.encode()
        return bcrypt.checkpw(input_password.encode(), has_and_salt)

    def decode_password(self, encoded, auth):
        return self.decode(encoded, auth)

    async def get_google_oauth_client_id(self) -> str:
        google_oauth = await OauthConfig.filter(provider="google")

        return google_oauth[0].client_id if google_oauth else ""

    async def get_identity_providers(self):
        providers = await OauthConfig.all()
        providers = [p for p in providers if p.enabled]

        return {
            idp.provider: idp.client_id
            for idp in providers
            if idp.provider != "easyauth"
        }

    async def generate_google_oauth_token(self, request=None, auth_code=None):
        """
        Generate a token for an existing User and/or create user using
        provided oauth2 token
        """
        google_oauth = await OauthConfig.filter(provider="google")

        if not google_oauth:
            raise GoogleOauthNotEnabledOrConfigured
        oauth_config = google_oauth[0]

        if not auth_code:
            # verify OAuth2 type
            google_client_type = request.headers.get("X-Google-OAuth2-Type")

            if google_client_type != "client":
                raise GoogleOauthHeaderMalformed

            body_bytes = await request.body()
            auth_code = jsonable_encoder(body_bytes)
        try:
            idinfo = id_token.verify_oauth2_token(
                auth_code, requests.Request(), oauth_config.client_id
            )

            if idinfo["email"] and idinfo["email_verified"]:
                email = idinfo.get("email")

            else:
                raise HTTPException(
                    status_code=400, detail="Unable to validate social login"
                )

        except Exception as e:
            self.log.exception("error validating social login")
            raise HTTPException(
                status_code=400, detail="Unable to validate social login"
            )
        # verify user exists
        user = await Users.filter(email=email)

        if not user:
            # does not exist, create
            result = await self.register_user(
                {
                    "username": email,
                    "email address": email,
                    "full name": f"{idinfo['given_name']} {idinfo['family_name']}",
                    "email": email,
                    "password": "",
                    "repeat password": "",
                    "groups": [g.group_name for g in oauth_config.default_groups],
                }
            )
            if "Activation email sent to" in result:
                return result

            # no activation was required
            user = await Users.filter(email=email)

        permissions = await self.get_user_permissions(user[0])

        return await self.issue_token(permissions)

    async def validate_user_pw(self, username, password) -> Union[Users, None]:
        user = await Users.get(username=username)

        if user:
            if user.account_type == "service":
                raise HTTPException(
                    status_code=401, detail="unable to login with service accounts"
                )

            try:
                try:
                    if not self.is_password_valid(user.password, password):
                        return None
                    return user
                except ValueError as e:
                    self.log.exception("error validating user_pw")
                return user
            except Exception as e:
                self.log.error(
                    f"Auth failed for user {user.username} - invalid credentials"
                )
        return None

    async def get_user_permissions(self, user: Union[Users, Services]) -> dict:
        """
        accepts validated user returned by validate_user_pw
        returns allowed permissions based on member group's roles / permissonis
        """
        permissions = {}

        for group in user.groups:
            for role in group.roles:
                for action in role.actions:
                    if "actions" not in permissions:
                        permissions["actions"] = []

                    if action not in permissions["actions"]:
                        permissions["actions"].append(action.action)
                if "roles" not in permissions:
                    permissions["roles"] = []
                if role not in permissions["roles"]:
                    permissions["roles"].append(role.role)
            if "groups" not in permissions:
                permissions["groups"] = []
            if group not in permissions["groups"]:
                permissions["groups"].append(group.group_name)
        permissions["users"] = [user.username]
        return permissions

    def router(
        self, path, method, permissions: list, send_token: bool = False, *args, **kwargs
    ):
        response_class = kwargs.get("response_class")

        def auth_endpoint(func):
            send_token = False
            send_request = False
            func_sig = signature(func)
            params = list(func_sig.parameters.values())
            for ind, param in enumerate(params.copy()):
                if param.name == "request" and param._annotation == Request:
                    send_request = True
                if param.name == "token" and param.annotation == str:
                    send_token = True
                    params.pop(ind)

            token_parameter = Parameter(
                "token",
                kind=Parameter.POSITIONAL_OR_KEYWORD,
                default=Depends(self.oauth2_scheme),
                annotation=str,
            )
            if not send_request:
                request_parameter = Parameter(
                    "request", kind=Parameter.POSITIONAL_OR_KEYWORD, annotation=Request
                )

            args_index = [str(p) for p in params]
            kwarg_index = None
            for i, v in enumerate(args_index):
                if "**" in v:
                    kwarg_index = i
            arg_index = None
            for i, v in enumerate(args_index):
                if "*" in v and not i == kwarg_index:
                    arg_index = i

            if arg_index:
                if not send_request:
                    params.insert(0, request_parameter)
                params.insert(arg_index - 1, token_parameter)
            elif not kwarg_index:
                if not send_request:
                    params.insert(0, request_parameter)
                params.append(token_parameter)
            ## ** kwargs
            else:
                if not send_request:
                    params.insert(0, request_parameter)
                params.insert(kwarg_index - 1, token_parameter)

            new_sig = func_sig.replace(parameters=params)

            @wraps(func, new_sig=new_sig)
            async def mock_function(*args, **kwargs):
                request = kwargs["request"]
                token = kwargs["token"]
                if token == "NO_TOKEN":
                    if (
                        response_class is HTMLResponse
                        or "text/html" in request.headers["accept"]
                    ):
                        response = HTMLResponse(
                            await self.get_login_page(
                                message="Login Required", request=request
                            ),
                            status_code=401,
                        )
                        response.set_cookie("token", "INVALID", **self.cookie_security)
                        response.set_cookie(
                            "ref",
                            request.__dict__["scope"]["path"],
                            **self.cookie_security,
                        )
                        return response

                try:
                    token = self.decode_token(token)[1]
                except Exception as e:
                    self.log.error("error decoding token")
                    if (
                        response_class is HTMLResponse
                        or "text/html" in request.headers["accept"]
                    ):
                        response = HTMLResponse(
                            await self.get_login_page(
                                message="Login Required", request=request
                            ),
                            status_code=401,
                        )
                        response.set_cookie("token", "INVALID", **self.cookie_security)
                        response.set_cookie(
                            "ref",
                            request.__dict__["scope"]["path"],
                            **self.cookie_security,
                        )
                        return response
                    raise HTTPException(
                        status_code=401, detail="not authorized, invalid or expired"
                    )
                if token["token_id"] not in self.store["tokens"]:
                    self.log.error(
                        f"token for user {token['permissions']['user'][0]} used is unknown / revoked"
                    )
                    if (
                        response_class is HTMLResponse
                        or "text/html" in request.headers["accept"]
                    ):
                        response = HTMLResponse(
                            await self.get_login_page(
                                message="Login Required", request=request
                            ),
                            status_code=401,
                        )
                        response.set_cookie("token", "INVALID", **self.cookie_security)
                        response.set_cookie(
                            "ref",
                            request.__dict__["scope"]["path"],
                            **self.cookie_security,
                        )
                        return response
                    raise HTTPException(
                        status_code=401, detail="not authorized, invalid or expired"
                    )

                allowed = False

                for auth_type, values in permissions.items():
                    if auth_type not in token["permissions"]:
                        self.log.warning(f"{auth_type} is required")
                        continue
                    for value in values:
                        if value in token["permissions"][auth_type]:
                            allowed = True
                            break

                if not allowed:
                    if response_class is HTMLResponse:
                        response = HTMLResponse(
                            await self.get_403_page(),  # self.admin.forbidden_page(),
                            status_code=403,
                        )
                        return response
                    raise HTTPException(
                        status_code=403,
                        detail=f"not authorized, permissions required: {permissions}",
                    )

                if "access_token" in kwargs:
                    kwargs["access_token"] = token

                if not send_token:
                    del kwargs["token"]
                if not send_request:
                    del kwargs["request"]

                result = func(*args, **kwargs)
                if asyncio.iscoroutine(result):
                    return await result
                return result

            mock_function.__name__ = func.__name__

            route = getattr(self.server, method)

            route(path, *args, **kwargs)(mock_function)
            return mock_function

        return auth_endpoint

    def parse_permissions(self, users, groups, roles, actions, default_permissions):
        """
        returns permssions defined on a given endpoint if set
        if unset
            returns router dedfault permissions
        if no router defaults
            return EasyAuthServer default permissions
        """
        permissions = {}
        if users:
            permissions["users"] = users
        if groups:
            permissions["groups"] = groups
        if roles:
            permissions["roles"] = roles
        if actions:
            permissions["actions"] = actions
        if not permissions:
            permissions = (
                self.DEFAULT_PERMISSION
                if not default_permissions
                else default_permissions
            )
        return permissions

    def get(
        self,
        path,
        users: list = None,
        groups: list = None,
        roles: list = None,
        actions: list = None,
        send_token: bool = False,
        *args,
        **kwargs,
    ):
        permissions = self.parse_permissions(users, groups, roles, actions)
        return self.router(
            path, "get", permissions=permissions, send_token=send_token, *args, **kwargs
        )

    def post(
        self,
        path,
        users: list = None,
        groups: list = None,
        roles: list = None,
        actions: list = None,
        send_token: bool = False,
        *args,
        **kwargs,
    ):
        permissions = self.parse_permissions(users, groups, roles, actions)
        return self.router(
            path,
            "post",
            permissions=permissions,
            send_token=send_token,
            *args,
            **kwargs,
        )

    def update(
        self,
        path,
        users: list = None,
        groups: list = None,
        roles: list = None,
        actions: list = None,
        send_token: bool = False,
        *args,
        **kwargs,
    ):
        permissions = self.parse_permissions(users, groups, roles, actions)
        return self.router(
            path,
            "udpate",
            permissions=permissions,
            send_token=send_token,
            *args,
            **kwargs,
        )

    def delete(
        self,
        path,
        users: list = None,
        groups: list = None,
        roles: list = None,
        actions: list = None,
        send_token: bool = False,
        *args,
        **kwargs,
    ):
        permissions = self.parse_permissions(users, groups, roles, actions)
        return self.router(
            path,
            "delete",
            permissions=permissions,
            send_token=send_token,
            *args,
            **kwargs,
        )

    def put(
        self,
        path,
        users: list = None,
        groups: list = None,
        roles: list = None,
        actions: list = None,
        send_token: bool = False,
        *args,
        **kwargs,
    ):
        permissions = self.parse_permissions(users, groups, roles, actions)
        return self.router(
            path, "put", permissions=permissions, send_token=send_token, *args, **kwargs
        )
