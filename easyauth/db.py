import os
from aiopyql import data
from easyauth.models import tables_setup

async def database_setup(server):
    """
    Expected Environment variables:
    DB_HOST 
    DB_PORT
    DB_NAME 
    DB_PASSWORD
    DB_TYPE [sqlite|mysql|postgres]
    """
    DB_TYPE = None

    assert 'DB_TYPE' in os.environ, f"missing required DB_TYPE env variable"
    assert 'DB_NAME' in os.environ, f"missing required DB_NAME env variable"

    DB_TYPE = os.environ['DB_TYPE']
    DB_NAME = os.environ['DB_NAME']
    
    if not DB_TYPE == 'sqlite':
        for env in {'DB_TYPE', 'DB_HOST', 'DB_PORT', 'DB_NAME', 'DB_USER', 'DB_PASSWORD'}:
            assert env in os.environ, f"missing required {env} env variable"
            
    if not DB_TYPE == 'sqlite':
        DB_HOST = os.environ['DB_HOST']
        DB_PORT = os.environ['DB_PORT']
        DB_USER = os.environ['DB_USER']
        DB_PASSWORD = os.environ['DB_PASSWORD']

        db = await data.Database.create(
            database=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD,
            host=DB_HOST,
            port=DB_PORT,
            db_type=DB_TYPE,
            cache_enabled=True,
            #debug=True
        )

    else:
        DB_LOCAL_PATH = os.environ.get('DB_LOCAL_PATH')
        DB_NAME = f"{DB_LOCAL_PATH}/{DB_NAME}" if DB_LOCAL_PATH else DB_NAME
        db = await data.Database.create(
            database=DB_NAME,
            cache_enabled=True,
            #debug=True
        )
    
    server.db = db
    