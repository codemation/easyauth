import os, uuid
import asyncio
import subprocess
from aiopyql import data
from easyrpc.tools.database import EasyRpcProxyDatabase
from easyauth.models import tables_setup

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
    DB_TYPE = None

    # create db_proxy.py in-place, used for centralizing db access
    # and allowing forking of EasyAuthServer
    #with open('db_proxy.py', 'w') as proxy:
    #    proxy.write(db_proxy)

    assert 'DB_TYPE' in os.environ, f"missing required DB_TYPE env variable"
    assert 'DB_NAME' in os.environ, f"missing required DB_NAME env variable"

    DB_TYPE = os.environ['DB_TYPE']
    DB_NAME = os.environ['DB_NAME']
    
    if not DB_TYPE == 'sqlite':
        for env in {'DB_TYPE', 'DB_HOST', 'DB_PORT', 'DB_NAME', 'DB_USER', 'DB_PASSWORD'}:
            assert env in os.environ, f"missing required {env} env variable"

    server.quorum_db = await data.Database.create(
        database='quorum'
    )

    member_id = str(uuid.uuid4())
    # create table
    await server.quorum_db.create_table(
        'quorum',
        [
            ('member_id', str, 'UNIQUE NOT NULL'),
            ('leader', bool),
            ('ready', bool)
        ],
        'member_id',
    )

    await server.quorum_db.create_table(
        'env',
        [
            ('key', str, 'UNIQUE NOT NULL'),
            ('value', str),
        ],
        'key',
    )

    await server.quorum_db.tables['quorum'].insert(
        member_id=member_id,
        leader=False,
        ready=False
    )
    # waiting for other members to join quorum
    await asyncio.sleep(2)

    # elect leader - first member to join
    
    members = await server.quorum_db.tables['quorum'].select('*')
    server.leader = False
    # declare self as leader, since inserted first
    if members[0]['member_id'] == member_id:
        server.log.warning(f"declaring {member_id} as leader")
        server.leader = True
        await server.quorum_db.tables['quorum'].update(
            leader=True,
            ready=True,
            where={'member_id': member_id}
        )

        RPC_SECRET = get_random_string(12)
        await server.quorum_db.tables['env'].insert(
            key='RPC_SECRET', value=RPC_SECRET
        )

        os.environ['RPC_SECRET'] = RPC_SECRET
        await asyncio.sleep(0.3)

        # create subprocess for db_proxy
        server.db_proxy = subprocess.Popen(
            f"gunicorn easyauth.db_proxy:server -w 1 -k uvicorn.workers.UvicornWorker -b 127.0.0.1:{db_proxy_port}".split(' ')
        )
        await asyncio.sleep(3)

    else:
        await asyncio.sleep(5)
        RPC_SECRET = await server.quorum_db.tables['env']['RPC_SECRET']
        os.environ['RPC_SECRET'] = RPC_SECRET


    DB_NAME = os.environ['DB_NAME']
    server.db = await EasyRpcProxyDatabase.create(
        '127.0.0.1', 
        db_proxy_port, 
        f'/ws/{DB_NAME}', 
        server_secret=RPC_SECRET,
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
        await server.quorum_db.tables['quorum'].update(
            ready=True,
            where={'member_id': member_id}
        )
        await asyncio.sleep(1)
        await server.quorum_db.close()
    else:
        async def db_cleanup():
            while not len(
                await server.quorum_db.tables['quorum'].select('ready', where={'ready': False})
            ) == 0:
                # leader waiting for members to complete - db setup
                await asyncio.sleep(1)
            await server.quorum_db.run('drop table quorum')
            await server.quorum_db.run('drop table env')
            await asyncio.sleep(1)
            await server.quorum_db.close()
        asyncio.create_task(db_cleanup())
    @server.server.on_event('shutdown')
    async def quorum_close():
        await server.quorum_db.close()