import os
import asyncio
from easyrpc.server import EasyRpcServer
from aiopyql.data import Database

def db_proxy_setup(server):

    @server.on_event('startup')
    async def db_setup():
        
        db_config = {}
        # get database type
        db_type = os.environ.get('DB_TYPE')
        if not db_type:
            raise Exception(f"missing required DB_TYPE environment variable")
        
        db_name = os.environ.get('DB_NAME')
        if not db_name:
            raise Exception(f"missing required DB_NAME environment variable")

        db_config['db_type'] = db_type
        db_config['database'] = db_name
        if db_type in {'mysql', 'postgres'}:
            for cfg in {'HOST','PORT', 'USER', 'PASSWORD'}:
                db_config[cfg.lower()] = os.environ.get(f"DB_{cfg}")
                if not db_config[cfg.lower()]:
                    raise Exception(f"missing required DB_{cfg} environment variable")
        else:
            sqlite_db_path = os.environ.get('DB_LOCAL_PATH')
            if sqlite_db_path:
                db_config['database'] = f"{sqlite_db_path}/{db_name}"
                
        db_cache = os.environ.get('DB_CACHE')
        if db_cache:
            db_config['cache_enabled'] = True if not db_cache == 0 else False
        else:
            db_config['cache_enabled'] = True
            
        rpc_config = {}
        
        rpc_secret = os.environ.get('RPC_SECRET')

        if not rpc_secret:
            raise Exception(f"missing required RPC_SECRET environment variable")
        rpc_path = os.environ.get('RPC_PATH')

        rpc_config['origin_path'] = rpc_path if rpc_path else f'/ws/{db_name}'
        rpc_config['server_secret'] = rpc_secret

        rcp_enryption = os.environ.get('RPC_ENCRYPTION')
        if rcp_enryption:
            rpc_config['encryption_enabled'] = True if rcp_enryption == 1 else False
        
        rpc_debug = os.environ.get('RPC_DEBUG')
        if rpc_debug:
            rpc_config['debug'] = True if rpc_debug == 'True' else False

        # Rpc Server
        db_server = await EasyRpcServer.create(
            server,
            **rpc_config
        )

        # insert logger
        db_config['log'] = db_server.log

        # Database Conection
        db = await Database.create(
            **db_config
        )

        # register each func table namespace
            
        def register_table(table):
            async def insert(**kwargs):
                return await db.tables[table].insert(**kwargs)
            insert.__name__ = f"{table}_insert"

            async def select(*args, **kwargs):
                return await db.tables[table].select(*args, **kwargs)
            select.__name__ = f"{table}_select"

            async def update(**kwargs):
                return await db.tables[table].update(**kwargs)
            update.__name__ = f"{table}_update"
            
            async def delete(**kwargs):
                return await db.tables[table].delete(**kwargs)
            delete.__name__ = f"{table}_delete"

            async def set_item(key, values):
                return await db.tables[table].set_item(key, values)
            set_item.__name__ = f"{table}_set_item"

            async def get_item(key_val):
                return await db.tables[table][key_val]
            get_item.__name__ = f"{table}_get_item"

            async def get_schema():
                return {
                    table: {
                        "primary_key": db.tables[table].prim_key,
                        "foreign_keys": db.tables[table].foreign_keys,
                        "columns": [
                            {
                                "name": col.name, "type": str(col.type.__name__), "mods": col.mods 
                            } for k, col in db.tables[table].columns.items() 
                        ],
                        "cache_enabled": db.tables[table].cache_enabled,
                        "max_cache_len": db.tables[table].max_cache_len
                    }
                }
            get_schema.__name__ = f"{table}_get_schema"

            for func in {insert, update, select, delete, select, get_schema, set_item, get_item}:
                db_server.origin(func, namespace=db_name)
        for table in db.tables:
            register_table(table)

        @db_server.origin(namespace=db_name)
        async def show_tables():
            table_list = []
            for table in db.tables:
                for func in {'insert', 'select', 'update', 'delete', 'set_item', 'get_item', 'get_schema'}:
                    if not f"{table}_{func}" in db_server.namespaces[db_name]:
                        register_table(table)
                        break
                table_list.append(table)
            return table_list

        @db_server.origin(namespace=db_name)
        async def create_table(
            name: str, 
            columns: list, 
            prim_key: str,
            **kw
        ):
            result = await db.create_table(
                name=name, 
                columns=columns, 
                prim_key=prim_key, 
                **kw
            )
            await show_tables()
            return result

        db_server.origin(db.run, namespace=db_name)

        server.db_server = db_server
        server.db = db


    @server.on_event('shutdown')
    async def shutdown():
        await server.db.close()

def manager_proxy_setup(server):

    @server.on_event('startup')
    async def manager_setup():
        rpc_config = {}
        
        rpc_secret = os.environ.get('RPC_SECRET')
        if not rpc_secret:
            raise Exception(f"missing required RPC_SECRET environment variable")
        rpc_path = os.environ.get('RPC_PATH')

        rpc_config['origin_path'] = '/ws/manager'
        rpc_config['server_secret'] = rpc_secret

        rcp_enryption = os.environ.get('RPC_ENCRYPTION')
        if rcp_enryption:
            rpc_config['encryption_enabled'] = True if rcp_enryption == 1 else False
        
        rpc_debug = os.environ.get('RPC_DEBUG')
        if rpc_debug:
            rpc_config['debug'] = True if rpc_debug == 'True' else False

        # Rpc Server
        manager = await EasyRpcServer.create(
            server,
            **rpc_config
        )
        log = manager.log

        @manager.origin(namespace='manager')
        async def global_store_update(action, store, key, value):
            #trigger all registered functions within 
            #clients namespace
            client_methods = manager['clients']
            log.warning(f"triggering global_store_update for {client_methods}")
            for method in client_methods:
                if method == 'get_store_data': 
                    continue
                try:
                    result = await client_methods[method](action, store, key, value)
                    log.warning(f"{result}")
                except Exception as e:
                    log.exception(f"error")

            return "global_store_update - completed"