import os
import bcrypt
import jwcrypto.jwk as jwk
import python_jwt as jwt
import jwt as pyjwt
import datetime
import json
import logging
import asyncio
from starlette.status import HTTP_302_FOUND
from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.security import OAuth2PasswordBearer
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from makefun import wraps
from inspect import signature, Parameter
#from fastapi_mail import FastMail, MessageSchema, ConnectionConfig

from easyauth.db import database_setup
from easyauth.models import tables_setup
from easyauth.api import api_setup
from easyauth.frontend import frontend_setup

class EasyAuthServer:
    def __init__(
        self, 
        server: FastAPI, 
        token_url: str,
        logger: logging.Logger = None,
        debug: bool = False,
        env_from_file: str = None,
        default_permission: dict = {'groups': ['administrators']}
    ):
        self.server = server
        self.server.title = 'EasyAuth'
        self.oauth2_scheme = OAuth2PasswordBearer(tokenUrl=token_url) # /token
        self.DEFAULT_PERMISSION = default_permission

        # logging setup # 
        self.log = logger
        self.debug = debug
        level = None if not self.debug else 'DEBUG'
        self.setup_logger(logger=self.log, level=level)

        if env_from_file:
            self.load_env_from_file(env_from_file)

        # env variable checks # 
        assert 'ISSUER' in os.environ, f"missing ISSUER env variable"
        assert 'SUBJECT' in os.environ, f"missing SUBJECT env variable"
        assert 'AUDIENCE' in os.environ, f"missing AUDIENCE env variable"
        assert 'KEY_PATH' in os.environ, f"missing KEY_PATH env variable"
        assert 'KEY_NAME' in os.environ, f"missing KEY_NAME env variable"

        # setup keys
        self.key_setup()

        # setup allowed origins - where can server receive token requests from
        self.cors_setup()

        @server.middleware('http')
        async def detect_token_in_cookie(request, call_next):
            request_dict = dict(request)
            request_header = dict(request.headers)
            token_in_cookie = None
            auth_ind = None
            cookie_ind = None

            for i, header in enumerate(request_dict['headers']):
                if 'authorization' in header[0].decode():
                    if not header[1] is None:
                        auth_ind = i
                if 'cookie' in header[0].decode():
                    cookie_ind = i
                    cookies = header[1].decode().split(',')
                    for cookie in cookies[0].split('; '):
                        key, value = cookie.split('=')
                        if key == 'token':
                            token_in_cookie = value
            if token_in_cookie and not token_in_cookie == 'INVALID':
                if auth_ind:
                    request_dict['headers'].pop(auth_ind)
                if not request_dict['path'] == '/login':
                    request_dict['headers'].append(
                        ('authorization'.encode(), f'bearer {token_in_cookie}'.encode())
                    )
                else:
                    return RedirectResponse('/logout')
            else:
                if not request_dict['path'] == '/login':
                    token_in_cookie = 'NO_TOKEN' if not token_in_cookie else token_in_cookie
                    request_dict['headers'].append(
                        ('authorization'.encode(), f'bearer {token_in_cookie}'.encode())
                    )

            return await call_next(request)
        

        @server.middleware('http')
        async def handle_401_403(request, call_next):
            response = await call_next(request)
            request_dict = dict(request)
            if response.status_code in [401, 404]:
                if 'text/html' in request.headers['accept']:
                    if response.status_code == 404:
                        return HTMLResponse(
                            self.admin.not_found_page(),
                            status_code=404
                        )
                    response = HTMLResponse(
                        self.admin.login_page(
                            welcome_message='Login Required'
                        ),
                        status_code=401
                    )
                    response.set_cookie('token', 'INVALID')
                    response.set_cookie('ref', request.__dict__['scope']['path'])
                    

            if response.status_code == 500:
                log.error(f"Internal error - 500 - with request: {request.__dict__}")
            return response

    @classmethod
    async def create(
        cls,
        server: FastAPI, 
        token_url: str,
        logger: logging.Logger = None,
        debug: bool = False,
        env_from_file: str = None,
        default_permission: dict = {'groups': ['administrators']}
    ):
        auth_server = cls(
            server,
            token_url,
            logger,
            debug,
            env_from_file,
            default_permission
        )
        await database_setup(auth_server)
        await tables_setup(auth_server)
        await api_setup(auth_server)
        await frontend_setup(auth_server)

        @server.on_event('shutdown')
        async def db_close():
            await auth_server.db.close()

        return auth_server

    def load_env_from_file(self, file_path):
        self.log.warning(f"loading env vars from {file_path}")
        with open(file_path, 'r') as json_env:
            env_file = json.load(json_env)
            for env, value in env_file.items():
                os.environ[env] = value

    def setup_logger(self, logger=None, level=None):
        if logger == None:
            level = logging.DEBUG if level == 'DEBUG' else logging.WARNING
            logging.basicConfig(
                level=level,
                format='%(asctime)s %(name)-12s %(levelname)-8s %(message)s',
                datefmt='%m-%d %H:%M'
            )
            self.log = logging.getLogger(f'EasyAuthServer')
            self.log.propogate = False
            self.log.setLevel(level)
        else:
            self.log = logger
    
    def key_setup(self):
        # check if keys exist in KEY_PATH else create

        try:
            with open(f"{os.environ['KEY_PATH']}/{os.environ['KEY_NAME']}.key", 'r') as k:
                pass
        except Exception:
            # create private / public keys
            key = jwk.JWK.generate(kty='RSA', size=2048)
            with open(f"{os.environ['KEY_PATH']}/{os.environ['KEY_NAME']}.key", 'w') as k:
                k.write(key.export_private())
        try:
            with open(f"{os.environ['KEY_PATH']}/{os.environ['KEY_NAME']}.pub", 'r') as k:
                pass
        except Exception:
            with open(f"{os.environ['KEY_PATH']}/{os.environ['KEY_NAME']}.pub", 'w') as pb:
                pb.write(key.export_private())

    def email_setup(self):
        self.email_conf = ConnectionConfig(**{
            "MAIL_USERNAME": os.environ['MAIL_USERNAME'],
            "MAIL_PASSWORD": os.environ['MAIL_PASSWORD'],
            "MAIL_FROM": os.environ['MAIL_FROM'],
            "MAIL_PORT": int(os.environ['MAIL_PORT']),
            "MAIL_SERVER": os.environ['MAIL_SERVER'],
            "MAIL_FROM_NAME": os.environ['MAIL_FROM_NAME'],
            "MAIL_TLS": True,
            "MAIL_SSL": False
        })
    async def send_email(subject: str, email: str, recipients: list):
        body = f"""<p>{email}</p>"""
        message = MessageSchema(
            subject=f"{subject}",
            recipients=[email],  # List of recipients, as many as you can pass 
            body=body,
            subtype="html"
        )

        fm = FastMail(conf)
        asyncio.create_task(fm.send_message(message))
        return {"message": "email has been sent", "otp": otp}

    def cors_setup(self):
        origins = ['*']

        self.server.add_middleware(
            CORSMiddleware,
            allow_origins=origins,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
    def issue_token(self, permissions, minutes=60, hours=0, days=0):

        payload = {
            'iss': os.environ['ISSUER'], 
            'sub': os.environ['SUBJECT'], 
            'aud': os.environ['AUDIENCE'],
            'permissions': permissions 
        }
        with open(f"{os.environ['KEY_PATH']}/{os.environ['KEY_NAME']}.key", 'r') as key_path:
            private_key = key_path.readline()
            return jwt.generate_jwt(
                payload, 
                jwk.JWK.from_json(private_key), 
                'RS256', 
                datetime.timedelta(minutes=minutes, hours=hours, days=days)
            )
    def decode_token(self, token):
        with open(f"{os.environ['KEY_PATH']}/{os.environ['KEY_NAME']}.pub", 'r') as pb_key:
            return jwt.verify_jwt(
                token, 
                jwk.JWK.from_json(pb_key.readline()), 
                ['RS256']
            )
    def encode(self, secret, **kw):
        try:
            return pyjwt.encode(kw, secret, algorithm='HS256')
        except Exception as e:
            self.log.exception(f"error encoding {kw} using {secret}")

    def decode(self, token, secret):
        return pyjwt.decode(token.encode('utf-8'), secret, algorithms='HS256')

    def encode_password(self, pw):
        hash_and_salt = bcrypt.hashpw(pw.encode(), bcrypt.gensalt())
        return hash_and_salt.decode()
    def is_password_valid(self, encoded, input_password):
        has_and_salt = encoded.encode()
        return bcrypt.checkpw(input_password.encode(), has_and_salt)


    def decode_password(self, encoded, auth):
        return self.decode(encoded, auth)

    async def validate_user_pw(self, username, password):
        user = await self.auth_users.select('*', where={'username': username})
        if len(user) > 0:
            if user[0]['account_type'] == 'service':
                raise HTTPException(status_code=401, detail=f"unable to login with service accounts")
            self.log.warning(f"checking auth for {user}")
            try:
                try:
                    if self.is_password_valid(user[0]['password'], password):
                        return user
                except ValueError:
                    pass

                # try old auth
                decoded_password = self.decode_password(user[0]['password'], password)
                self.log.warning(f"old password used: - updating")
                await self.auth_users.update(
                    password=self.encode_password(decoded_password['password']),
                    where={'username': username}
                )
                return user
            except Exception as e:
                self.log.error(f"Auth failed for user {user} - invalid credentials")
        return None
    async def get_user_permissions(self, username: str) -> list:
        """
        accepts validated user returned by validate_user_pw
        returns allowed permissions based on member group's roles / permissonis
        """
        user = await self.auth_users.select('*', where={'username': username})
        user = user[0]

        permissions = {}
        groups = user['groups']['groups']
        for group in groups:
            group_data = await self.auth_groups.select('*', where={'group_name': group})
            if not group_data:
                self.log.error(f"group {group} not found in groups table")
                continue
            group_data = group_data[0]

            if isinstance(group_data['roles'], dict):
                group_data['roles'] = group_data['roles']['roles']
            for role in group_data['roles']:
                role_info = await self.auth_roles.select('*', where={'role': role})
                if not role_info:
                    self.log.error(f"role {role} not found in roles table - {role_info}")
                    continue
                role_info = role_info[0]
                if isinstance(role_info['permissions'], dict):
                    role_info['permissions'] = role_info['permissions']['actions']
                for action in role_info['permissions']:
                    if not 'actions' in permissions:
                        permissions['actions'] = []
                    
                    if not action in permissions['actions']:
                        action_info = await self.auth_actions.select(
                            'action', where={'action': action}
                        )
                        if not action_info:
                            self.log.error(f"action {action} not found in actions table- {action_info}")
                            continue
                        permissions['actions'].append(action)
                if not 'roles' in permissions:
                    permissions['roles'] = []
                if not role in permissions['roles']:
                    permissions['roles'].append(role)
            if not 'groups' in permissions:
                permissions['groups'] = []
            if not group in permissions['groups']:
                permissions['groups'].append(group)
        permissions['users'] = [user['username']]
        return permissions

    def router(self, path, method, permissions: list, send_token: bool = False, *args, **kwargs):
        response_class = kwargs.get('response_class')

        def auth_endpoint(func):
            send_token = False
            send_request = False
            func_sig = signature(func)
            params = list(func_sig.parameters.values())
            for ind, param in enumerate(params.copy()):
                if param.name == 'request' and param._annotation == Request:
                    send_request = True
                if param.name == 'token' and param.annotation == str:
                    send_token = True
                    params.pop(ind)

            token_parameter = Parameter(
                'token', 
                kind=Parameter.POSITIONAL_OR_KEYWORD, 
                default=Depends(self.oauth2_scheme), 
                annotation=str
            )
            if not send_request:
                request_parameter = Parameter(
                        'request', 
                        kind=Parameter.POSITIONAL_OR_KEYWORD,
                        annotation=Request
                    )

            args_index = [str(p) for p in params]
            kwarg_index = None
            for i, v in enumerate(args_index):
                if '**' in v:
                    kwarg_index = i
            arg_index = None
            for i, v in enumerate(args_index):
                if '*' in v and not i == kwarg_index:
                    arg_index = i
            
            if arg_index:
                if not send_request:
                    params.insert(0, request_parameter)
                params.insert(arg_index-1, token_parameter)
            elif not kwarg_index:
                if not send_request:
                    params.insert(0, request_parameter)
                params.append(token_parameter)
            ## ** kwargs
            else:
                if not send_request:
                    params.insert(0, request_parameter)
                params.insert(kwarg_index-1, token_parameter)

            new_sig = func_sig.replace(parameters=params)
            @wraps(func, new_sig=new_sig)
            async def mock_function(*args, **kwargs):
                request = kwargs['request']
                token = kwargs['token']
                if token ==  'NO_TOKEN':
                    if response_class is HTMLResponse or 'text/html' in request.headers['accept']:
                        response = HTMLResponse(
                            self.admin.login_page(
                                welcome_message='Login Required'
                            ),
                            status_code=401
                        )
                        response.set_cookie('token', 'INVALID')
                        response.set_cookie('ref', request.__dict__['scope']['path'])
                        return response


                try:
                    token = self.decode_token(token)[1]
                    self.log.debug(f"decoded token: {token}")
                except Exception:
                    self.log.exception(f"error decoding token")
                    if response_class is HTMLResponse:
                        response = HTMLResponse(
                            self.admin.login_page(
                                welcome_message='Login Required'
                            ),
                            status_code=401
                        )
                        response.set_cookie('token', 'INVALID')
                        response.set_cookie('ref', request.__dict__['scope']['path'])
                        return response
                    raise HTTPException(status_code=401, detail=f"not authorized, invalid or expired")

                allowed = False
                for auth_type, values in permissions.items():
                    if not auth_type in token['permissions']:
                        self.log.warning(f"{auth_type} is required")
                        continue
                    for value in values:
                        if value in token['permissions'][auth_type]:
                            allowed = True
                            break
                if not allowed:
                    if response_class is HTMLResponse:
                        response = HTMLResponse(
                            self.admin.forbidden_page(),
                            status_code=403
                        )
                        response.set_cookie('token', 'INVALID')
                        return response
                    raise HTTPException(
                        status_code=403, 
                        detail=f"not authorized, permissions required: {permissions}"
                    )

                if 'access_token' in kwargs:
                    kwargs['access_token'] = token 

                if not send_token:
                    del kwargs['token']
                if not send_request:
                    del kwargs['request']
                
                result = func(*args, **kwargs)
                if asyncio.iscoroutine(result): 
                    return await result
                return result

            mock_function.__name__ = func.__name__       

            route = getattr(self.server, method)

            route(path, *args, **kwargs)(mock_function)
            return mock_function
        return auth_endpoint


    def parse_permissions(self, users, groups, roles, actions):
        permissions = {}
        if users:
            permissions['users'] = users
        if groups:
            permissions['groups'] = groups
        if roles:
            permissions['roles'] = roles
        if actions:
            permissions['actions'] = actions
        if not permissions:
            permissions = self.DEFAULT_PERMISSION
        return permissions
        
    def get(
        self, 
        path, 
        users: list = None, 
        groups: list= None, 
        roles: list = None, 
        actions: list = None, 
        send_token: bool = False,
        *args, 
        **kwargs
    ):
        permissions = self.parse_permissions(users, groups, roles, actions)
        return self.router(path, 'get', permissions=permissions, send_token=send_token, *args, **kwargs)
    def post(
        self, 
        path, 
        users: list = None, 
        groups: list= None, 
        roles: list = None, 
        actions: list = None, 
        send_token: bool = False,
        *args, 
        **kwargs
    ):
        permissions = self.parse_permissions(users, groups, roles, actions)
        return self.router(path, 'post', permissions=permissions, send_token=send_token, *args, **kwargs)
    def update(
        self, 
        path, 
        users: list = None, 
        groups: list= None, 
        roles: list = None, 
        actions: list = None, 
        send_token: bool = False,
        *args, 
        **kwargs
    ):
        permissions = self.parse_permissions(users, groups, roles, actions)
        return self.router(path, 'udpate', permissions=permissions, send_token=send_token, *args, **kwargs)
    def delete(
        self, 
        path, 
        users: list = None, 
        groups: list= None, 
        roles: list = None, 
        actions: list = None,
        send_token: bool = False,
        *args, 
        **kwargs
    ):
        permissions = self.parse_permissions(users, groups, roles, actions)
        return self.router(path, 'delete', permissions=permissions, send_token=send_token, *args, **kwargs)
    def put(
        self, 
        path, 
        users: list = None, 
        groups: list= None, 
        roles: list = None, 
        actions: list = None, 
        send_token: bool = False,
        *args, 
        **kwargs
    ):
        permissions = self.parse_permissions(users, groups, roles, actions)
        return self.router(path, 'put', permissions=permissions, send_token=send_token, *args, **kwargs)