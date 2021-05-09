import os
from fastapi import FastAPI

from easyauth.server import EasyAuthServer

server = FastAPI()

AUTH_SECRET = os.environ.get('AUTH_SECRET')
ADMIN_TITLE = os.environ.get('ADMIN_TITLE')
ADMIN_PREFIX = os.environ.get('ADMIN_PREFIX')

if not AUTH_SECRET:
    AUTH_SECRET = 'abcd1234'

if not ADMIN_TITLE:
    ADMIN_TITLE = 'EasyAuth - Example'

if not ADMIN_PREFIX:
    ADMIN_PREFIX = '/admin'

@server.on_event('startup')
async def startup():
    server.auth = await EasyAuthServer.create(
        server, 
        '/auth/token',
        admin_title=ADMIN_TITLE,
        admin_prefix=ADMIN_PREFIX
    )