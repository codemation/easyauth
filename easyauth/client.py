import os
import jwcrypto.jwk as jwk
import python_jwt as jwt
import jwt as pyjwt
import datetime
import json
import logging
import asyncio
from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from makefun import wraps
from inspect import signature, Parameter


class EasyAuthClient:
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
        assert 'KEY_PATH' in os.environ, f"missing KEY_PATH env variable"
        assert 'KEY_NAME' in os.environ, f"missing KEY_NAME env variable"

    @classmethod
    async def create(
        cls,
        server: FastAPI, 
        token_url: str,
        logger: logging.Logger = None,
        debug: bool = False,
        env_from_file: str = None
    ):
        auth_server = cls(
            server,
            token_url,
            logger,
            debug,
            env_from_file
        )

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
    

    def decode_token(self, token):
        with open(f"{os.environ['KEY_PATH']}/{os.environ['KEY_NAME']}.pub", 'r') as pb_key:
            return jwt.verify_jwt(
                token, 
                jwk.JWK.from_json(pb_key.readline()), 
                ['RS256']
            )

    def router(self, path, method, permissions: list, send_token: bool, *args, **kwargs):
        def auth_endpoint(func):
            
            func_sig = signature(func)
            params = list(func_sig.parameters.values())

            token_parameter = Parameter(
                    'token', 
                    kind=Parameter.POSITIONAL_OR_KEYWORD, 
                    default=Depends(self.oauth2_scheme), 
                    annotation=str
                )

            print(params)
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
                params.insert(arg_index-1, token_parameter)
            elif not kwarg_index is None and arg_index is None:
                print(f"kwargs only")
                params.insert(kwarg_index, token_parameter)
            else:
                params.append(token_parameter)
            print(f"kwarg_index: {kwarg_index} argindex: {arg_index}")
            print(params)
            
                    
            """
            params.append(
                Parameter(
                    'token', 
                    kind=Parameter.POSITIONAL_OR_KEYWORD, 
                    default=Depends(self.oauth2_scheme), 
                    annotation=str
                )
            )
            """
            new_sig = func_sig.replace(parameters=params)

            @wraps(func, new_sig=new_sig)
            async def mock_function(token: str = Depends(self.oauth2_scheme), *args, **kwargs):
                try:
                    print(token)
                    token = self.decode_token(token)[1]
                    print(f"decoded token: {token}")
                except Exception:
                    self.log.exception(f"error decoding token")
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
                    raise HTTPException(
                        status_code=401, 
                        detail=f"not authorized, permissions required: {permissions}"
                    )
                if send_token:
                    kwargs['access_token'] = token
                    result = func(*args, **kwargs)
                else:
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