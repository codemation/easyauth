import asyncio
import json
import logging
import os
import sys
import uuid
from inspect import Parameter, signature
from typing import Any, List

import jwcrypto.jwk as jwk
import python_jwt as jwt
from aiohttp.client_exceptions import ClientConnectorError
from easyadmin import Admin
from easyadmin.elements import buttons, forms, html_input, modal, scripts
from easyadmin.pages import register
from easyrpc.exceptions import ServerConnectionError, ServerUnreachable
from easyrpc.server import EasyRpcServer
from easyschedule import EasyScheduler
from fastapi import Depends, FastAPI, Form, HTTPException, Request, Response
from fastapi.encoders import jsonable_encoder
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.security import OAuth2PasswordBearer
from jwcrypto.jws import InvalidJWSSignature
from makefun import wraps
from pydbantic import Database, DataBaseModel, Default, PrimaryKey
from starlette.status import HTTP_302_FOUND

from easyauth.exceptions import EasyAuthClientToServerConnectionError
from easyauth.models import ActivationCode
from easyauth.pages import (
    ActivationPage,
    ForbiddenPage,
    LoginPage,
    NotFoundPage,
    RegisterPage,
)
from easyauth.router import EasyAuthAPIRouter


class LogFilter:
    def __init__(self, logger, filters: List[Exception]):
        self.log = logger
        self.filters = filters

    def info(self, *args):
        self.log.info(*args)

    def warning(self, *args):
        self.log.warning(*args)

    def error(self, *args):
        self.log.error(*args)

    def debug(self, *args):
        self.log.debug(*args)

    def exception(self, *args) -> bool:
        if sys.exc_info()[0] in self.filters:
            self.log.error(*args)
            return True
        else:
            self.log.exception(*args)
            return False


class EasyAuthClient:
    def __init__(
        self,
        server: FastAPI,
        auth_secret: str,
        token_server: str = None,
        token_server_port: int = None,
        logger: logging.Logger = None,
        env_from_file: str = None,
        debug: bool = False,
        default_permissions: dict = {"groups": ["administrators"]},
        secure: bool = False,
        default_login_path: str = "/login",
        default_login_redirect: str = "/",
    ):
        self.server = server
        self.token_server = token_server
        self.token_server_port = token_server_port

        self.default_permissions = default_permissions

        self.admin = Admin("EasyAuthClient", side_bar_sections=[])

        # cookie security
        self.cookie_security = {
            "secure": secure,
            "samesite": "lax" if not secure else "none",
        }

        # default login path
        self.default_login_path = default_login_path
        self.default_login_redirect = default_login_redirect

        # ensure new routers created follow same oath scheme
        EasyAuthAPIRouter.parent = self
        for page in {
            LoginPage,
            RegisterPage,
            ActivationPage,
            NotFoundPage,
            ForbiddenPage,
        }:
            page.parent = self

        self.auth_secret = auth_secret
        self.oauth2_scheme = OAuth2PasswordBearer(tokenUrl=self.default_login_path)

        # extra routers
        self.api_routers = []

        # logging setup #
        self.log = logger
        self.debug = debug
        level = None if not self.debug else "DEBUG"
        self.setup_logger(logger=self.log, level=level)

        if env_from_file:
            self.load_env_from_file(env_from_file)

    @classmethod
    def create(
        cls,
        server: FastAPI,
        token_url: str = None,
        token_server: str = None,
        token_server_port: int = None,
        auth_secret: str = None,
        logger: logging.Logger = None,
        debug: bool = False,
        env_from_file: str = None,
        default_permissions: str = {"groups": ["administrators"]},
        default_login_redirect: str = "/",
        secure: bool = False,
        default_login_path="/login",
    ):
        setup_error = None
        for arg in {auth_secret}:
            assert not auth_secret is None, f"Expected value for 'auth_secret'"

        # disect token URL, extract host:port
        if token_url:
            token_server, token_server_port = token_url.split("/")[2].split(":")

        log = LogFilter(
            logging.getLogger("EasyAuthClient"),
            filters=[
                ServerUnreachable,
                ServerConnectionError,
                ConnectionRefusedError,
                ClientConnectorError,
            ],
        )

        auth_server = cls(
            server,
            auth_secret,
            token_server,
            token_server_port,
            logger,
            debug,
            env_from_file,
            default_permissions,
            secure,
            default_login_path,
            default_login_redirect,
        )

        @server.on_event("startup")
        async def auth_setup():
            await auth_server.setup()

        @server.middleware("http")
        async def detect_token_in_cookie(request, call_next):
            request_dict = dict(request)
            token_in_cookie = None
            auth_ind = None
            cookie_ind = None
            for i, header in enumerate(request_dict["headers"]):
                if "authorization" in header[0].decode():
                    if not header[1] is None:
                        auth_ind = i
                if "cookie" in header[0].decode():
                    cookie_ind = i
                    cookies = header[1].decode().split(",")
                    for cookie in cookies[0].split("; "):
                        key, value = cookie.split("=")
                        if key == "token":
                            token_in_cookie = value
            if token_in_cookie and not token_in_cookie == "INVALID":
                if auth_ind:
                    request.headers.__dict__["_list"].pop(auth_ind)
                if request_dict["path"] != f"{auth_server.default_login_path}":
                    request.headers.__dict__["_list"].append(
                        ("authorization".encode(), f"bearer {token_in_cookie}".encode())
                    )
                else:
                    return RedirectResponse("/logout")
            else:
                if not request_dict["path"] == f"{auth_server.default_login_path}":
                    token_in_cookie = (
                        "NO_TOKEN" if not token_in_cookie else token_in_cookie
                    )
                    request_dict["headers"].append(
                        ("authorization".encode(), f"bearer {token_in_cookie}".encode())
                    )
            response = await call_next(request)
            if response.status_code == 404 and "text/html" in request.headers["accept"]:
                if hasattr(auth_server, "html_not_found_page"):
                    return HTMLResponse(
                        auth_server.html_not_found_page(), status_code=404
                    )

                return HTMLResponse(auth_server.admin.not_found_page(), status_code=404)
            return response

        return auth_server

    async def setup(self):
        rpc_server = EasyRpcServer(
            self.server, "/ws/easyauth", server_secret=self.auth_secret, logger=self.log
        )
        self.rpc_server = rpc_server

        try:
            await rpc_server.create_server_proxy(
                self.token_server,
                self.token_server_port,
                "/ws/easyauth",
                server_secret=self.auth_secret,
                namespace="global_store",
            )

            await rpc_server.create_server_proxy(
                self.token_server,
                self.token_server_port,
                "/ws/easyauth",
                server_secret=self.auth_secret,
                namespace="easyauth",
            )

        except Exception:
            setup_error = self.log.exception(
                f"error creating connction to EasyAuthServer {self.token_server}:{self.token_server_port}"
            )

        setup_info = await rpc_server["easyauth"]["get_setup_info"]()

        self.token_url = setup_info["token_url"]
        self._public_key = jwk.JWK.from_json(setup_info["public_rsa"])

        setup_info = await rpc_server["easyauth"]["get_setup_info"]()

        self.scheduler = EasyScheduler()

        @self.scheduler("* * * * *")
        async def refresh_auth_public_key():
            try:
                setup_info = await rpc_server["easyauth"]["get_setup_info"]()
                self._public_key = jwk.JWK.from_json(setup_info["public_rsa"])
            except IndexError as e:
                self.log.error(
                    f"Unable to refresh_auth_public_key - connection with EasyAuthServer {self.token_server}:{self.token_server_port} may have failed"
                )

        asyncio.create_task(self.scheduler.start())
        await asyncio.sleep(5)

        self.store = await rpc_server["global_store"]["get_store_data"]()

        async def store_data(action: str, store: str, key: str, value: Any = None):
            """
            actions:
                - put|update|delete
            """
            self.log.debug(
                f"store_data action: {action} - store: {store} - key: {key} - value: {value}"
            )

            if not store in self.store:
                self.store[store] = {}
            if action in {"update", "put"}:
                self.log.info(f"token updated: {key}")
                self.store[store][key] = value
            else:
                if key in self.store[store]:
                    del self.store[store][key]

            return f"{action} in {store} with {key} completed"

        store_data.__name__ = store_data.__name__ + "_".join(
            str(uuid.uuid4()).split("-")
        )

        rpc_server.origin(store_data, namespace="global_store")

        @self.server.get(
            f"{self.default_login_path}",
            response_class=HTMLResponse,
            include_in_schema=False,
        )
        async def login(request: Request, response: Response):
            return await self.get_login_page(message="Login to Begin", request=request)

        @self.server.post(
            f"{self.default_login_path}/re",
            response_class=HTMLResponse,
            include_in_schema=False,
        )
        async def login(request: Request, response: Response):
            response.delete_cookie("ref")

        self.log.warning(f"adding routers")
        await self.include_routers()

        @self.server.post(
            f"{self.default_login_path}",
            tags=["Login"],
            response_class=HTMLResponse,
            include_in_schema=False,
        )
        async def login_page(
            request: Request,
            response: Response,
            username: str = Form(...),
            password: str = Form(...),
        ):
            token = None
            token = await self.rpc_server["easyauth"]["generate_auth_token"](
                username, password
            )

            if not "access_token" in token:
                message = (
                    "invalid username / password"
                    if "invalid username / password" in token
                    else token
                )
                return HTMLResponse(
                    await self.get_login_page(message=message, request=request),
                    status_code=401,
                )
            token = token["access_token"]
            token_id = self.decode_token(token)[1]["token_id"]
            self.store["tokens"][token_id] = ""

            response.set_cookie("token", token, **self.cookie_security)
            response.status_code = 200

            redirect_ref = self.default_login_redirect
            if "ref" in request.cookies:
                redirect_ref = request.cookies["ref"]
                response.delete_cookie("ref")

            return RedirectResponse(
                redirect_ref, headers=response.headers, status_code=HTTP_302_FOUND
            )

        @self.server.get("/register", response_class=HTMLResponse, tags=["User"])
        async def admin_register():
            return self.server.html_register_page()

        @RegisterPage.mark()
        def default_register_page():
            return register.get_register_user_page(
                form=forms.get_form(
                    title="Register User",
                    rows=[
                        html_input.get_text_input("username", size=12),
                        html_input.get_text_input(
                            "password", input_type="password", size=12
                        ),
                        html_input.get_text_input(
                            "repeat password", input_type="password", size=12
                        ),
                        html_input.get_text_input("full name", size=12),
                        html_input.get_text_input("email address", size=12),
                    ],
                    submit_name="Register User",
                    action="/register",
                    transform_id="RegisterUser",
                )
            )

        @self.server.post("/register", response_class=HTMLResponse, tags=["User"])
        async def admin_register_send(user_info: dict):
            return await auth_server.rpc_server["easyauth"]["register_user"](user_info)

        @self.server.get("/activate", response_class=HTMLResponse, tags=["User"])
        async def admin_activate():
            return self.server.html_activation_page()

        @ActivationPage.mark()
        def default_activate_page():
            return register.get_register_user_page(
                form=forms.get_form(
                    title="Activate User",
                    welcome_message="Activate your account",
                    rows=[html_input.get_text_input("activation_code", size=12)],
                    submit_name="Activate",
                    action="/activate",
                    transform_id="ActivateUser",
                )
            )

        @self.server.post("/activate", response_class=HTMLResponse, tags=["User"])
        async def admin_activate_send(activation_code: ActivationCode):
            return await self.rpc_server["easyauth"]["activate_user"](
                activation_code.dict()
            )

        @self.server.post("/auth/token/oauth/google", include_in_schema=False)
        async def create_google_oauth_token(
            request: Request,
            response: Response,
            redirect: bool = True,
            include_token: bool = False,
        ):

            google_client_type = request.headers.get("X-Google-OAuth2-Type")

            if google_client_type == "client":
                body_bytes = await request.body()
                auth_code = jsonable_encoder(body_bytes)
            token = await self.rpc_server["easyauth"]["generate_google_oauth_token"](
                auth_code
            )

            response.set_cookie("token", token, **self.cookie_security)

            redirect_ref = "/"

            if "ref" in request.cookies:
                redirect_ref = request.cookies["ref"]
                response.delete_cookie("ref")

            if redirect:
                return RedirectResponse(
                    redirect_ref, headers=response.headers, status_code=HTTP_302_FOUND
                )

            # not redirecting

            decoded_token = self.decode_token(token)[1]
            response_body = {"exp": decoded_token["exp"], "auth": True}
            if include_token:
                response_body["token"] = token
            return HTMLResponse(
                content=json.dumps(response_body),
                status_code=200,
                headers=response.headers,
            )

        @self.server.get(
            "/logout",
            tags=["Login"],
            response_class=HTMLResponse,
            include_in_schema=False,
        )
        async def logout_page(response: Response):
            response.set_cookie("token", "INVALID", **self.cookie_security)
            return RedirectResponse(
                f"{self.default_login_path}", headers=response.headers
            )

        @self.server.get(
            "/logout",
            tags=["Login"],
            response_class=HTMLResponse,
            include_in_schema=False,
        )
        async def logout_page(response: Response):
            response.set_cookie("token", "INVALID")
            return RedirectResponse(
                f"{self.default_login_path}", headers=response.headers
            )

        @self.server.post(
            "/logout",
            tags=["Login"],
            response_class=HTMLResponse,
            include_in_schema=False,
        )
        async def logout_page_post(
            response: Response,
        ):
            response.set_cookie("token", "INVALID", **self.cookie_security)
            return RedirectResponse(
                f"{self.default_login_path}/re", headers=response.headers
            )

    async def include_routers(self):
        for auth_api_router in self.api_routers:
            self.server.include_router(auth_api_router.server)

    def create_api_router(self, *args, **kwargs):
        api_router = EasyAuthAPIRouter.create(*args, **kwargs)
        self.api_routers.append(api_router)
        return api_router

    async def get_403_page(self):
        if hasattr(self, "html_forbidden_page"):
            return self.html_forbidden_page()

        body = f"""
            <div class="text-center">
                <div class="error mx-auto" data-text="Forbidden">Forbidden</div>
                <p class="text-gray-500 mb-0">You dont have permission to view this</p>
                <a href="{self.default_login_path}">&larr; Back to Login</a>
            </div>
        """
        logout_modal = modal.get_modal(
            f"logoutModal",
            alert="Ready to Leave",
            body=buttons.get_button("Go Back", color="success", href=f"/")
            + scripts.get_google_signout_script()
            + buttons.get_button("Log out", color="danger", onclick="signOut()"),
            footer="",
            size="sm",
        )
        identity_providers = await self.rpc_server["easyauth"][
            "get_identity_providers"
        ]()
        return self.admin.admin_page(
            name="",
            body="",
            topbar_extra=body,
            current_user="",
            modals=logout_modal,
            **identity_providers,
        )

    async def get_login_page(self, message, request: Request = None, **kwargs):
        redirect_ref = "/"
        if request and "ref" in request.cookies:
            redirect_ref = request.cookies["ref"]
        identity_providers = await self.rpc_server["easyauth"][
            "get_identity_providers"
        ]()

        if hasattr(self, "html_login_page"):
            return self.html_login_page()

        return self.admin.login_page(
            welcome_message=message,
            login_action=f"{self.default_login_path}",
            **identity_providers,
            google_redirect_url=redirect_ref,
        )

    def load_env_from_file(self, file_path):
        self.log.warning(f"loading env vars from {file_path}")
        with open(file_path, "r") as json_env:
            env_file = json.load(json_env)
            for env, value in env_file.items():
                os.environ[env] = value

    def setup_logger(self, logger=None, level=None):
        if logger == None:
            level = logging.DEBUG if level == "DEBUG" else logging.WARNING
            logging.basicConfig(
                level=level,
                format="%(asctime)s %(name)-12s %(levelname)-8s %(message)s",
                datefmt="%m-%d %H:%M",
            )
            self.log = logging.getLogger(f"EasyAuthServer")
            self.log.propogate = False
            self.log.setLevel(level)
        else:
            self.log = logger

    def decode_token(self, token):
        return jwt.verify_jwt(token, self._public_key, ["RS256"])

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
                if token in {"NO_TOKEN", "INVALID"}:
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
                    if isinstance(e, InvalidJWSSignature):
                        self.log.error(
                            f"EasyAuthClient failed to decode token - keys may have rotated - login wil be required"
                        )
                    else:
                        self.log.exception(f"error decoding token")
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
                        # response.headers["ref"] = request.__dict__["scope"]["path"]
                        return response
                    raise HTTPException(
                        status_code=401, detail=f"not authorized, invalid or expired"
                    )

                allowed = False
                for auth_type, values in permissions.items():
                    if not auth_type in token["permissions"]:
                        self.log.warning(f"{auth_type} is required")
                        continue
                    for value in values:
                        if value in token["permissions"][auth_type]:
                            allowed = True
                            break

                if not token["token_id"] in self.store["tokens"]:
                    self.log.error(
                        f"token for user {token['permissions']['users'][0]} - {token['token_id']} is unknown / revoked {self.store['tokens']}"
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
                        # response.headers["ref"] = request.__dict__["scope"]["path"]
                        return response
                    raise HTTPException(
                        status_code=401, detail=f"not authorized, invalid or expired"
                    )

                if not allowed:
                    if (
                        response_class is HTMLResponse
                        or "text/html" in request.headers["accept"]
                    ):
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
            return EasyAuthClient default permissions
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
                self.default_permissions
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
        permissions = self.parse_permissions(
            users, groups, roles, actions, self.default_permissions
        )
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
        permissions = self.parse_permissions(
            users, groups, roles, actions, self.default_permissions
        )
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
        permissions = self.parse_permissions(
            users, groups, roles, actions, self.default_permissions
        )
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
        permissions = self.parse_permissions(
            users, groups, roles, actions, self.default_permissions
        )
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
        permissions = self.parse_permissions(
            users, groups, roles, actions, self.default_permissions
        )
        return self.router(
            path, "put", permissions=permissions, send_token=send_token, *args, **kwargs
        )

    def patch(
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
        permissions = self.parse_permissions(
            users, groups, roles, actions, self.default_permissions
        )
        return self.router(
            path,
            "patch",
            permissions=permissions,
            send_token=send_token,
            *args,
            **kwargs,
        )

    def options(
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
        permissions = self.parse_permissions(
            users, groups, roles, actions, self.default_permissions
        )
        return self.router(
            path,
            "options",
            permissions=permissions,
            send_token=send_token,
            *args,
            **kwargs,
        )

    def head(
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
        permissions = self.parse_permissions(
            users, groups, roles, actions, self.default_permissions
        )
        return self.router(
            path,
            "head",
            permissions=permissions,
            send_token=send_token,
            *args,
            **kwargs,
        )
