from typing import Optional

from fastapi import FastAPI

from easyauth.client import EasyAuthClient
from easyauth.pages import NotFoundPage

server = FastAPI(openapi_url="/groups/openapi.json")


@server.on_event("startup")
async def startup():
    server.auth = await EasyAuthClient.create(
        server,
        "http://0.0.0.0:8520/auth/token",  # Should be a running EasyAuthServer
        auth_secret="abcd1234",
        default_login_path="/login",
    )

    # grants access to only specified users
    @server.auth.get("/", users=["jane"])
    async def root():
        return "I am root"

    # grants access to members of 'users' or 'admins' group.
    @server.auth.get("/groups", groups=["users", "admins"])
    async def groups():
        return "I am groups"

    # grants access to all members of group which a role of 'basic' or advanced, or member 'users' group
    @server.auth.get("/roles", roles=["basic", "advanced"], groups=["users"])
    async def roles():
        return "I am roles"

    # grants access to all members of groups with a roles granting 'BASIC_CREATE'
    # accesssing the auth token
    @server.auth.get(
        "/actions", actions=["BASIC_CREATE"], groups=["administrators"], send_token=True
    )
    async def action(access_token: Optional[str] = None):
        return f"I am actions with token {access_token}"

    @NotFoundPage.mark()
    def unimplemented_not_found():
        return f"TODO - not found"
