import os, uuid
import jwcrypto.jwk as jwk
import python_jwt as jwt
import json
import logging
import asyncio
from typing import Any
from starlette.status import HTTP_302_FOUND
from fastapi import FastAPI, Depends, HTTPException, Form, Response, Request
from fastapi.security import OAuth2PasswordBearer
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.encoders import jsonable_encoder
from makefun import wraps
from inspect import signature, Parameter
from easyauth.models import ActivationCode
from easyadmin import Admin
from easyauth.router import EasyAuthAPIRouter
from easyrpc.server import EasyRpcServer

from easyadmin.elements import (
    scripts,
    modal,
    buttons,
    card,
    forms,
    html_input
)
from easyadmin.pages import admin, register


class EasyAuthClient:
    def __init__(self,
        server: FastAPI,
        rpc_server: EasyRpcServer,
        token_url: str,
        public_key: str,
        logger: logging.Logger = None,
        env_from_file: str = None,
        debug: bool = False,
        default_permission: dict = {'groups': ['administrators']}
    ):
        self.server = server
        self.oauth2_scheme = OAuth2PasswordBearer(tokenUrl=token_url) # /token
        self.DEFAULT_PERMISSION = default_permission

        self.admin = Admin('EasyAuthClient', side_bar_sections=[])
        self.token_url = token_url
        self._public_key = jwk.JWK.from_json(public_key)

        self.rpc_server = rpc_server

        # extra routers
        self.api_routers = []

        # logging setup # 
        self.log = logger
        self.debug = debug
        level = None if not self.debug else 'DEBUG'
        self.setup_logger(logger=self.log, level=level)

        if env_from_file:
            self.load_env_from_file(env_from_file)

        # env variable checks #
        #assert 'KEY_PATH' in os.environ, f"missing KEY_PATH env variable"
        #assert 'KEY_NAME' in os.environ, f"missing KEY_NAME env variable"

    @classmethod
    async def create( cls,
        server: FastAPI,
        token_url: str = None,
        token_server: str = None,
        token_server_port: int = None,
        auth_secret: str = None,
        logger: logging.Logger = None,
        debug: bool = False,
        env_from_file: str = None,
        default_permissions: str = {'groups': ['administrators']},
        default_login_redirect: str = '/'
    ):
        for arg in {auth_secret}:
            assert not auth_secret is None, f"Expected value for 'auth_secret'"

        # TODO - Depricate token_url usage in later releases
        # TODO - Depricate env_from_file usage - accepts now, but has no effect

        # disect token URL, extract host:port
        if token_url:
            token_server, token_server_port = token_url.split('/')[2].split(':')

        rpc_server = EasyRpcServer(
            server, 
            '/ws/easyauth',
            server_secret=auth_secret
        )

        await rpc_server.create_server_proxy(
            token_server, 
            token_server_port, 
            '/ws/easyauth', 
            server_secret=auth_secret, 
            namespace='global_store'
        )

        await rpc_server.create_server_proxy(
            token_server, 
            token_server_port, 
            '/ws/easyauth', 
            server_secret=auth_secret, 
            namespace='easyauth'
        )

        setup_info = await rpc_server['easyauth']['get_setup_info']()

        auth_server = cls(
            server,
            rpc_server,
            f"http://{token_server}:{token_server_port}{setup_info['token_url']}",
            setup_info['public_rsa'],
            logger,
            debug,
            env_from_file,
            default_permissions
        )
        await asyncio.sleep(5)
        
        auth_server.store = await rpc_server['global_store']['get_store_data']()

        async def store_data(action: str, store: str, key: str, value: Any = None):
            """
            actions:
                - put|update|delete
            """
            auth_server.log.debug(f"store_data action: {action} - store: {store} - key: {key} - value: {value}")
            if not store in auth_server.store:
                auth_server.store[store] = {}
            if action in {'update', 'put'}:
                auth_server.store[store][key] = value
            else:
                if key in auth_server.store[store]:
                    del auth_server.store[store][key]
            
            return f"{action} in {store} with {key} completed"

        store_data.__name__ = store_data.__name__ + '_'.join(
            str(uuid.uuid4()).split('-')
        )

        rpc_server.origin(store_data, namespace='global_store')

        @server.get('/login', response_class=HTMLResponse, include_in_schema=False)
        async def login(request: Request, response: Response):
            return await auth_server.get_login_page(
                message="Login to Begin",
                request=request
            )
        
        @server.post('/login/re', response_class=HTMLResponse, include_in_schema=False)
        async def login(request: Request, response: Response):
            response.delete_cookie('ref')
        
        @server.on_event('startup')
        async def setup():
            auth_server.log.warning(f"adding routers")
            await auth_server.include_routers()

        @server.post("/login", tags=['Login'], response_class=HTMLResponse, include_in_schema=False)
        async def login_page(
            request: Request,
            response: Response,
            username: str = Form(...), 
            password: str = Form(...),
        ):
            token = None
            token = await auth_server.rpc_server['easyauth']['generate_auth_token'](
                username, password
            )
            if not 'access_token' in token:
                message = 'invalid username / password' if 'invalid username / password' in token else token
                return await auth_server.get_login_page(
                    message=message,
                    request=request
                )
            response.set_cookie('token', token['access_token'])
            response.status_code=200
            
            redirect_ref = default_login_redirect
            if 'ref' in request.cookies:
                redirect_ref = request.cookies['ref']
                response.delete_cookie('ref')

            return RedirectResponse(
                redirect_ref, 
                headers=response.headers, 
                status_code=HTTP_302_FOUND
            )

        @server.get('/register', response_class=HTMLResponse, tags=['User'])
        async def admin_register():
            return register.get_register_user_page(
                form = forms.get_form(
                    title='Register User',
                    rows=[
                        html_input.get_text_input('username', size=12),
                        html_input.get_text_input('password', input_type='password',  size=12),
                        html_input.get_text_input('repeat password', input_type='password',  size=12),
                        html_input.get_text_input('full name', size=12),
                        html_input.get_text_input('email address', size=12)
                    ],
                    submit_name='Register User',
                    action="/register",
                    transform_id='RegisterUser'
                )
            )
        @server.post('/register', response_class=HTMLResponse, tags='User')
        async def admin_register_send(user_info: dict):
            return await auth_server.rpc_server['easyauth']['register_user'](
                user_info
            )

        @server.get('/activate', response_class=HTMLResponse, tags=['User'])
        async def admin_activate():
            return register.get_register_user_page(
                form = forms.get_form(
                    title='Activate User',
                    welcome_message='Activate your account',
                    rows=[
                        html_input.get_text_input('activation_code', size=12)
                    ],
                    submit_name='Activate',
                    action="/activate",
                    transform_id='ActivateUser'
                )
            )

        @server.post('/activate', response_class=HTMLResponse, tags='User')
        async def admin_activate_send(activation_code: ActivationCode):
            return await auth_server.rpc_server['easyauth']['activate_user'](
                activation_code.dict()
            )
        @server.post('/auth/token/oauth/google', include_in_schema=False)
        async def create_google_oauth_token(request: Request, response: Response):
            google_client_type = request.headers.get("X-Google-OAuth2-Type")

            if google_client_type == 'client':
                body_bytes = await request.body()
                auth_code = jsonable_encoder(body_bytes)
            token = await auth_server.rpc_server['easyauth']['generate_google_oauth_token'](
                auth_code
            )

            response.set_cookie('token', token)

            redirect_ref = '/'

            if 'ref' in request.cookies:
                redirect_ref = request.cookies['ref']
                response.delete_cookie('ref')

            return RedirectResponse(redirect_ref, headers=response.headers, status_code=HTTP_302_FOUND)

        @server.get("/logout", tags=['Login'], response_class=HTMLResponse, include_in_schema=False)
        async def logout_page(
            response: Response
        ):
            response.set_cookie('token', 'INVALID')
            return RedirectResponse('/login', headers=response.headers)

        @server.post("/logout", tags=['Login'], response_class=HTMLResponse, include_in_schema=False)
        async def logout_page_post(
            response: Response,
        ):
            response.set_cookie('token', 'INVALID')
            return RedirectResponse('/login/re', headers=response.headers)

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
            response = await call_next(request)
            if response.status_code == 404 and 'text/html' in request.headers['accept']:
                return HTMLResponse(
                    auth_server.admin.not_found_page(),
                    status_code=404
                )
            return response
        return auth_server

    async def include_routers(self):
        for auth_api_router in self.api_routers:
            self.server.include_router(auth_api_router.server)

    def create_api_router(self, *args, **kwargs):
        api_router = EasyAuthAPIRouter.create(self, *args, **kwargs)
        self.api_routers.append(
            api_router
        )
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
            f'logoutModal',
            alert='Ready to Leave',
            body=buttons.get_button(
                'Go Back',
                color='success',
                href=f'/'
            ) +
            scripts.get_google_signout_script() + 
            buttons.get_button(
                'Log out',
                color='danger',
                onclick='signOut()'
            ),
            footer='',
            size='sm'
        )
        identity_providers = await self.rpc_server['easyauth']['get_identity_providers']()
        return self.admin.admin_page(
            name='',
            body='',
            topbar_extra=body,
            current_user='',
            modals=logout_modal,
            **identity_providers
        )

    async def get_login_page(self, message, request: Request = None, **kwargs):
        redirect_ref = '/'
        if request and 'ref' in request.cookies:
            redirect_ref = request.cookies['ref']
        identity_providers = await self.rpc_server['easyauth']['get_identity_providers']()

        return self.admin.login_page(
            welcome_message=message,
            login_action='/login',
            **identity_providers,
            google_redirect_url = redirect_ref
        )

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
    

    def decode_token(self, token):
        #with open(f"{os.environ['KEY_PATH']}/{os.environ['KEY_NAME']}.pub", 'r') as pb_key:
        return jwt.verify_jwt(
            token, 
            self._public_key, 
            ['RS256']
        )

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
                            await self.get_login_page(
                                message='Login Required',
                                request=request
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
                            await self.get_login_page(
                                message='Login Required',
                                request=request
                            ),
                            status_code=401
                        )
                        response.set_cookie('token', 'INVALID')
                        response.headers['ref'] = request.__dict__['scope']['path']
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

                if not token['token_id'] in self.store['tokens']:
                    self.log.error(
                        f"token for user {token['permissions']['users'][0]} - {token['token_id']} is unknown / revoked {self.store['tokens']}"
                    )
                    allowed = False

                if not allowed:
                    if response_class is HTMLResponse or 'text/html' in request.headers['accept']:
                        response = HTMLResponse(
                            await self.get_403_page(), #self.admin.forbidden_page(),
                            status_code=403
                        )
                        #response.set_cookie('token', 'INVALID')
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
    def patch(
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
        return self.router(path, 'patch', permissions=permissions, send_token=send_token, *args, **kwargs)
    def options(
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
        return self.router(path, 'options', permissions=permissions, send_token=send_token, *args, **kwargs)
    def head(
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
        return self.router(path, 'head', permissions=permissions, send_token=send_token, *args, **kwargs)