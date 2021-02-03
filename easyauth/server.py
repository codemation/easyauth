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
from fastapi.middleware.cors import CORSMiddleware
from makefun import wraps
from inspect import signature, Parameter

from easyauth.db import database_setup
from easyauth.models import tables_setup
from easyauth.api import api_setup


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
        await database_setup(auth_server)
        await tables_setup(auth_server)
        await api_setup(auth_server)

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
        return self.encode(pw, password=pw)

    def decode_password(self, encodedPw, auth):
        return self.decode(encodedPw, auth)
    async def validate_user_pw(self, username, password):
        user = await self.db.tables['users'].select('*', where={'username': username})
        if len(user) > 0:
            if user[0]['account_type'] == 'service':
                raise HTTPException(status_code=401, detail=f"unable to login with service accounts")
            self.log.warning(f"checking auth for {user}")
            try:
                decoded = self.decode_password(user[0]['password'], password)
                return user
            except Exception as e:
                self.log.exception(f"Auth failed for user {user} - invalid credentials")
        return None
    async def get_user_permissions(self, user: dict) -> list:
        """
        accepts validated user returned by validate_user_pw
        returns allowed permissions based on member group's roles / permissonis
        """
        groups_table = self.db.tables['groups']
        roles_table = self.db.tables['roles']
        permissions = {}
        groups = user['groups']['groups']
        for group in groups:
            group_info = await groups_table[group]
            if not group_info:
                self.log.error(f"group {group} not found in groups table")
            for role in group_info['roles']:
                role_info = await roles_table[role]
                if not role_info:
                    self.log.error(f"role {role} not found in roles table")
                for action in role_info['actions']:
                    if not 'actions' in permissions:
                        permissions['actions'] = []
                    permissions['actions'].append(action)
                if not 'roles' in permissions:
                    permissions['roles'] = []
                permissions['roles'].append(role)
            if not 'groups' in permissions:
                permissions['groups'] = []
            permissions['groups'].append(group)
        permissions['users'] = [user['username']]
        return permissions

    def router(self, path, method, permissions: list, send_token: bool, *args, **kwargs):
        def auth_endpoint(func):
            
            func_sig = signature(func)
            params = list(func_sig.parameters.values())
            params.append(
                Parameter(
                    'token', 
                    kind=Parameter.POSITIONAL_OR_KEYWORD, 
                    default=Depends(self.oauth2_scheme), 
                    annotation=str
                )
            )
            new_sig = func_sig.replace(parameters=params)

            @wraps(func, new_sig=new_sig)
            async def mock_function(token: str = Depends(self.oauth2_scheme), *args, **kwargs):
                try:
                    print(token)
                    token = self.decode_token(token)[1]
                    print(f"decoded token: {token}")
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
                        self.log.warning(f"{value} in {auth_type} is required")
                        raise HTTPException(
                            status_code=401, 
                            detail=f"not authorized, permissions required: {permissions}"
                        )
                except Exception:
                    self.log.exception(f"error decoding token")
                    raise HTTPException(status_code=401, detail=f"not authorized, or toke may be invalid or expired")
                if send_token:
                    result = func(token=token, *args, **kwargs)
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