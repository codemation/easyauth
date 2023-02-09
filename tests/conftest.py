import asyncio
import os
import subprocess
import time

import pytest
import requests
from fastapi import FastAPI
from fastapi.testclient import TestClient

from easyauth import get_user
from easyauth.router import EasyAuthAPIRouter
from easyauth.server import EasyAuthServer

# import sub modules


def get_db_config():
    if not os.environ.get("ENV"):
        assert f"missing ENV environment variable [sqlite|mysql|postgres]"

    if os.environ["ENV"] == "mysql":
        return {
            "DB_TYPE": "mysql",
            "DB_NAME": "auth-db",
            "DB_HOST": "127.0.0.1",
            "DB_USER": "josh",
            "DB_PASSWORD": "abcd1234",
            "DB_PORT": "3306",
        }
    if os.environ["ENV"] == "postgres":
        return {
            "DB_TYPE": "postgresql",
            "DB_NAME": "auth-db",
            "DB_HOST": "127.0.0.1",
            "DB_USER": "postgres",
            "DB_PASSWORD": "postgres",
            "DB_PORT": "6379",
        }
    if os.environ["ENV"] == "sqlite":
        return {
            "DB_TYPE": "sqlite",
            "DB_NAME": "auth-db",
        }
    os.environ["TEST_INIT_PASSWORD"] = "easyauth"


@pytest.fixture()
def db_config():
    for key, value in get_db_config().items():
        os.environ[key] = value
    p = (
        subprocess.Popen(
            f"docker-compose -f docker/test-docker/auth-{os.environ['ENV']}.yml up -d db".split(
                " "
            )
        )
        if not os.environ["ENV"] == "sqlite"
        else None
    )
    time.sleep(20)
    yield

    p = (
        subprocess.Popen(
            f"docker-compose -f docker/test-docker/auth-{os.environ['ENV']}.yml down".split(
                " "
            )
        )
        if not os.environ["ENV"] == "sqlite"
        else None
    )


@pytest.fixture(scope="session")
def event_loop():

    policy = asyncio.get_event_loop_policy()
    loop = policy.new_event_loop()
    yield loop

    loop.close()


@pytest.fixture()
def db_and_auth_server():
    for key, value in get_db_config().items():
        os.environ[key] = value
    p = (
        subprocess.Popen(
            f"docker-compose -f docker/test-docker/auth-{os.environ['ENV']}.yml up -d db".split(
                " "
            )
        )
        if not os.environ["ENV"] == "sqlite"
        else None
    )
    time.sleep(20)
    p = subprocess.Popen(
        f"docker-compose -f docker/test-docker/auth-{os.environ['ENV']}.yml up -d auth".split(
            " "
        )
    )
    time.sleep(10)
    yield

    p = (
        subprocess.Popen(
            f"docker-compose -f docker/test-docker/auth-{os.environ['ENV']}.yml down".split(
                " "
            )
        )
        if not os.environ["ENV"] == "sqlite"
        else None
    )


@pytest.mark.asyncio
@pytest.fixture()
async def auth_test_server(db_config, event_loop):
    server = FastAPI()

    os.environ["EASYAUTH_PATH"] = os.environ["PWD"]

    @server.on_event("startup")
    async def setup():
        server.auth = await EasyAuthServer.create(
            server,
            "/auth/token",
            auth_secret="abcd1234",
            admin_title="EasyAuth - Company",
            admin_prefix="/admin",
        )

        from .finance import finance
        from .hr import hr
        from .marketing import marketing

        # test_auth_router = server.auth.create_api_router(prefix='/testing', tags=['testing'])
        test_auth_router = EasyAuthAPIRouter.create(prefix="/testing", tags=["testing"])

        # grants access to users matching default_permissions
        @test_auth_router.get("/default")
        async def default():
            return "I am default"

        # grants access to only specified users
        @test_auth_router.get("/", users=["john"])
        async def root():
            return "I am root"

        # grants access to members of 'users' or 'admins' group.
        @test_auth_router.get("/groups", groups=["basic_users", "admins"])
        async def groups():
            return "I am groups"

        # grants access to all members of 'users' group
        # or a groups with role of 'basic' or advanced
        @test_auth_router.get("/roles", roles=["basic", "advanced"], groups=["users"])
        async def roles():
            return "Roles and Groups"

        # grants access to all members of groups with a roles granting 'BASIC_CREATE'
        @test_auth_router.get("/actions", actions=["BASIC_CREATE"])
        async def action():
            return "I am actions"

        @test_auth_router.get("/current_user", users=["john"])
        async def current_user(user: str = get_user()):
            return user

        print(f"app - startup completed")

    with TestClient(app=server) as test_cleint:
        yield test_cleint


class AuthClient:
    def __init__(self, host: str = "0.0.0.0", port: str = "8521"):
        self.host = host
        self.port = port

    def get(self, path, *args, **kwargs):
        url = f"http://{self.host}:{self.port}{path}"
        return requests.get(url, *args, **kwargs)

    def post(self, path, *args, **kwargs):
        url = f"http://{self.host}:{self.port}{path}"
        return requests.post(url, *args, **kwargs)


@pytest.fixture()
def auth_test_client(db_and_auth_server):
    client_process = subprocess.Popen(
        f"uvicorn --host 0.0.0.0 --port 8521 tests.test_client:server".split(" ")
    )
    auth_client = AuthClient()
    time.sleep(12)
    yield auth_client
    client_process.kill()
