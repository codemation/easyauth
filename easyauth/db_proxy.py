from fastapi import FastAPI
from easyauth.proxy import db_proxy_setup
server = FastAPI()
db_proxy_setup(server)