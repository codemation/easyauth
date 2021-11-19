import os
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from easyauth import EasyAuthServer
# import sub modules
from .finance import finance
from .hr import hr
from .marketing import marketing

@pytest.mark.asyncio
@pytest.fixture()
async def auth_test_client():
    server = FastAPI()

    os.environ['EASYAUTH_PATH'] = os.environ['PWD']

    @server.on_event('startup')
    async def startup():
        server.auth = await EasyAuthServer.create(
            server, 
            '/auth/token',
            auth_secret='abcd1234',
            admin_title='EasyAuth - Company',
            admin_prefix='/admin',
            env_from_file='tests/server_sqlite.json'
        )

        finance_auth_router = server.auth.create_api_router(prefix='/finance', tags=['finance'])
        hr_auth_router = server.auth.create_api_router(prefix='/hr', tags=['hr'])
        marketing_auth_router = server.auth.create_api_router(prefix='/marketing', tags=['marketing'])

        # send auth routers to setup of each sub-module
        await finance.setup(finance_auth_router)
        await hr.setup(hr_auth_router)
        await marketing.setup(marketing_auth_router)
        #nothings

        test_auth_router = server.auth.create_api_router(prefix='/testing', tags=['testing'])

        # grants access to users matching default_permissions
        @test_auth_router.get('/default')
        async def default():
            return f"I am default"

        # grants access to only specified users
        @test_auth_router.get('/', users=['john'])
        async def root():
            return f"I am root"

        # grants access to members of 'users' or 'admins' group.
        @test_auth_router.get('/groups', groups=['basic_users', 'admins'])
        async def groups():
            return f"I am groups"

        # grants access to all members of 'users' group 
        # or a groups with role of 'basic' or advanced
        @test_auth_router.get('/roles', roles=['basic', 'advanced'], groups=['users'])
        async def roles():
            return f"Roles and Groups"

        # grants access to all members of groups with a roles granting 'BASIC_CREATE'
        @test_auth_router.get('/actions', actions=['BASIC_CREATE'])
        async def action():
            return f"I am actions"

    with TestClient(server) as test_client:
        yield test_client