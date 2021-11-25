import os

from pydbantic import Database

from easyauth.quorum import quorum_setup
from easyauth.models import (
    Users,
    Services,
    Groups,
    Roles,
    Actions,
    Tokens,
    PendingUsers,
    EmailConfig,
    OauthConfig,
    tables_setup
)


import random, string
def get_random_string(length):
    letters = string.ascii_lowercase
    result_str = ''.join(random.choice(letters) for i in range(length))
    return result_str

async def database_setup(server):
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
        conf = {}
        for env in {'DB_TYPE', 'DB_HOST', 'DB_PORT', 'DB_NAME', 'DB_USER', 'DB_PASSWORD'}:
            assert env in os.environ, f"missing required {env} env variable"
            conf[env] = os.environ[env]

        DB_URL = f"{conf['DB_TYPE']}://{conf['DB_USER']}:{conf['DB_PASSWORD']}@{conf['DB_HOST']}/{conf['DB_NAME']}"
    else:
         DB_URL = f"{DB_TYPE}:///{DB_NAME}"


    server.db = await Database.create(
        DB_URL=DB_URL,
        tables=[
            Users,
            Services,
            Groups,
            Roles,
            Actions,
            Tokens,
            PendingUsers,
            EmailConfig,
            OauthConfig,
        ],
        logger=server.log
    )

    await tables_setup(server)