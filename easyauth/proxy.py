import asyncio
import os

from easyrpc.server import EasyRpcServer
from easyschedule import EasyScheduler


def manager_proxy_setup(server):
    @server.on_event("startup")
    async def manager_setup():
        rpc_config = {}

        rpc_secret = os.environ.get("RPC_SECRET")
        if not rpc_secret:
            raise Exception(f"missing required RPC_SECRET environment variable")
        rpc_path = os.environ.get("RPC_PATH")

        rpc_config["origin_path"] = "/ws/manager"
        rpc_config["server_secret"] = rpc_secret

        rcp_enryption = os.environ.get("RPC_ENCRYPTION")
        if rcp_enryption:
            rpc_config["encryption_enabled"] = True if rcp_enryption == 1 else False

        rpc_debug = os.environ.get("RPC_DEBUG")
        if rpc_debug:
            rpc_config["debug"] = True if rpc_debug == "True" else False

        # Rpc Server
        manager = await EasyRpcServer.create(server, **rpc_config)
        log = manager.log
        manager.scheduler = EasyScheduler()

        @manager.origin(namespace="manager")
        async def global_store_update(action, store, key, value):
            # trigger all registered functions within
            # clients namespace
            client_methods = manager["clients"]
            for method in client_methods:
                if method == "get_store_data":
                    continue
                if "token_cleanup" in method:
                    continue

                try:
                    asyncio.create_task(
                        client_methods[method](action, store, key, value)
                    )
                except Exception as e:
                    log.exception(
                        f"error with {method} on k: {key} - v: {value} in {store}"
                    )

            return "global_store_update - completed"

        @manager.scheduler(schedule="*/15 * * * *")
        async def global_token_cleanup():
            """
            triggers check and cleanup of expired tokens
            """
            client_methods = manager["clients"]
            log.debug(f"triggering global_token_cleanup for {client_methods}")
            for method in client_methods:
                if not "token_cleanup" in method:
                    continue
                await client_methods[method]()
                break

        # start scheduler in background
        asyncio.create_task(manager.scheduler.start())
