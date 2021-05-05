from fastapi import FastAPI
from easyauth.proxy import manager_proxy_setup

server = FastAPI()
manager_proxy_setup(server)