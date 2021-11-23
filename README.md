![](./images/logo_t.png)
<br>

---

Create a centralized Authentication and Authorization token server. Easily secure FastAPI endpoints based on Users, Groups, Roles or Permissions to minimize database access requirements of Auth.

[![Documentation Status](https://readthedocs.org/projects/easyauth/badge/?version=latest)](https://easyauth.readthedocs.io/en/latest/?badge=latest) [![PyPI version](https://badge.fury.io/py/easy-auth.svg)](https://pypi.org/project/easy-auth/)

<h2>Documentation</h1>

[https://easyauth.readthedocs.io/en/latest/](https://easyauth.readthedocs.io/en/latest/)

## Key Features

- Centralized Auth - Single location for Users & Permissions to share across apps
- Granular Endpoint Security - Verify user identity, and define explicitly who and what each user or groups of users may access
- Admin GUI - easy management of users, permissions, tokens, oauth and more!
- Advanced JWT - Token Based Client authorization with built in invalidation capabilities
- Google Oauth - Easy to configure google login
- Integrated Login & Cookie Management - Users are not just authenticated and authorized, they are re-directed on token expiration to login pages via cookie system and sent back to last location afterwards

## Quick Start

```bash

$ virtualenv -p <python3.X> easy-auth-env
$ source easy-auth-env/bin/activate

(easy-auth) $ pip install easy-auth[server]

(easy-auth) $ pip install easy-auth[client] # without db

```

## Basic Server

Configure require env variables via a .json

```Bash
$ cat > server_env.json <<EOF
{
    "DB_TYPE": "sqlite",
    "DB_NAME": "auth",
    "ISSUER": "EasyAuth",
    "SUBJECT": "EasyAuthAuth",
    "AUDIENCE": "EasyAuthApis",
    "KEY_PATH": "/my_key-location",
    "KEY_NAME": "test_key"
}
EOF
```

```python
#test_server.py
from fastapi import FastAPI

from easyauth.server import EasyAuthServer

server = FastAPI()

@server.on_event('startup')
async def startup():
    server.auth = await EasyAuthServer.create(
        server,
        '/auth/token',
        auth_secret='abcd1234',
        admin_title='EasyAuth - Company',
        admin_prefix='/admin',
        env_from_file='server_env.json'
    )

```

Start Sever

```bash
uvicorn --host 0.0.0.0 --port 8330 test_server:server
```

## Basic Client

```python
#test_client.py
from fastapi import FastAPI

from easyauth.client import EasyAuthClient

server = FastAPI()

@server.on_event('startup')
async def startup():
    server.auth = await EasyAuthClient.create(
        server,
        token_server='0.0.0.0',
        token_server_port=8090,
        auth_secret='abcd1234',
        default_permissions={'groups': ['users']}
    )

    # grants access to users matching default_permissions
    @server.auth.get('/default')
    async def default():
        return f"I am default"

    # grants access to only specified users
    @server.auth.get('/', users=['jane'])
    async def root():
        return f"I am root"

    # grants access to members of 'users' or 'admins' group.
    @server.auth.get('/groups', groups=['users', 'admins'])
    async def groups():
        return f"I am groups"

    # grants access to all members of 'users' group
    # or a groups with role of 'basic' or advanced
    @server.auth.get('/roles', roles=['basic', 'advanced'], groups=['users'])
    async def roles():
        return f"Roles and Groups"

    # grants access to all members of groups with a roles granting 'BASIC_CREATE'
    @server.auth.get('/actions', actions=['BASIC_CREATE'])
    async def action():
        return f"I am actions"
```

![](docs/images/login.png)

## Server

<h3>See 0.0.0.0:8330/docs </h3>

![](docs/images/api/api.png)

### GUI

![](docs/images/admin_gui.png)

## Client

![](images/client.png)

![](images/OAuth.png)
