# proxy that allows auth workers to notify members
# 
#
manager_proxy = """
import os
from fastapi import FastAPI
from easyrpc.server import EasyRpcServer
from easyauth.proxy import manager_proxy_setup

server = FastAPI()
manager_proxy_setup(server)
"""