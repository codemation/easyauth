from fastapi import FastAPI

from easyauth.pages import LoginPage
from easyauth.server import EasyAuthServer

server = FastAPI()


server.auth = EasyAuthServer.create(
    server,
    "/auth/token",
    auth_secret="abcd1234",
    env_from_file="tests/server_sqlite.json",
)

from tests.finance import finance
from tests.hr.hr import hr_router
from tests.marketing import marketing
