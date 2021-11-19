from fastapi import FastAPI

from easyauth.server import EasyAuthServer

server = FastAPI()

@server.on_event('startup')
async def startup():
    server.auth = await EasyAuthServer.create(
        server,
        '/auth/token',
        auth_secret='abcd1234',
        env_from_file='server_sqlite.json'
    )