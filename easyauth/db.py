import os
import asyncio
import subprocess
from easyrpc.tools.database import EasyRpcProxyDatabase
from easyauth.quorum import quorum_setup

import random, string
def get_random_string(length):
    letters = string.ascii_lowercase
    result_str = ''.join(random.choice(letters) for i in range(length))
    return result_str

async def database_setup(server, db_proxy_port):
    """
    Expected Environment variables:
    DB_HOST 
    DB_PORT
    DB_NAME 
    DB_PASSWORD
    DB_TYPE [sqlite|mysql|postgres]
    """
    await quorum_setup(server)
    DB_TYPE = None

    assert 'DB_TYPE' in os.environ, f"missing required DB_TYPE env variable"
    assert 'DB_NAME' in os.environ, f"missing required DB_NAME env variable"

    DB_TYPE = os.environ['DB_TYPE']
    DB_NAME = os.environ['DB_NAME']
    
    if not DB_TYPE == 'sqlite':
        for env in {'DB_TYPE', 'DB_HOST', 'DB_PORT', 'DB_NAME', 'DB_USER', 'DB_PASSWORD'}:
            assert env in os.environ, f"missing required {env} env variable"

    if server.leader:

        # create subprocess for db_proxy
        server.db_proxy = subprocess.Popen(
            f"gunicorn easyauth.db_proxy:server -w 1 -k uvicorn.workers.UvicornWorker -b 127.0.0.1:{db_proxy_port}".split(' ')
        )
        await asyncio.sleep(3)

    DB_NAME = os.environ['DB_NAME']
    server.db = await EasyRpcProxyDatabase.create(
        '127.0.0.1', 
        db_proxy_port, 
        f'/ws/{DB_NAME}', 
        server_secret=os.environ['RPC_SECRET'],
        namespace=f'{DB_NAME}'
    )

    # check for completeness of db setup
    while not 'liveness' in server.db.tables:
        server.log.warning(f"waiting for db setup to complete")
        await asyncio.sleep(2)
    
    if not server.leader:
        while not 'users' in server.db.tables:
            server.log.warning(f"waiting for leader to complete - db setup")
            await asyncio.sleep(2)