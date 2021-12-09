import asyncio
from inspect import Parameter, signature

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import HTMLResponse
from makefun import wraps


class EasyAuthAPIRouter:
    parent = None

    def __init__(
        self,
        parent,  # EasyAuthClient or EasyAuthServer,
        api_router: APIRouter,
        default_permissions: dict = None,
    ):
        self.parent = parent
        self.server = api_router
        self.parent.api_routers.append(self)
        self.log = parent.log
        self.default_permissions = default_permissions

    @classmethod
    def create(cls, default_permissions: dict = None, *args, **kwargs):
        api_router = APIRouter(*args, **kwargs)
        auth_api_router = cls(cls.parent, api_router, default_permissions)
        return auth_api_router

    def router(
        self, path, method, permissions: list, send_token: bool = False, *args, **kwargs
    ):
        response_class = kwargs.get("response_class")

        def auth_endpoint(func):
            send_token = False
            send_request = False
            func_sig = signature(func)
            params = list(func_sig.parameters.values())
            for ind, param in enumerate(params.copy()):
                if param.name == "request" and param._annotation == Request:
                    send_request = True
                if param.name == "token" and param.annotation == str:
                    send_token = True
                    params.pop(ind)

            token_parameter = Parameter(
                "token",
                kind=Parameter.POSITIONAL_OR_KEYWORD,
                default=Depends(self.parent.oauth2_scheme),
                annotation=str,
            )
            if not send_request:
                request_parameter = Parameter(
                    "request", kind=Parameter.POSITIONAL_OR_KEYWORD, annotation=Request
                )

            args_index = [str(p) for p in params]
            kwarg_index = None
            for i, v in enumerate(args_index):
                if "**" in v:
                    kwarg_index = i
            arg_index = None
            for i, v in enumerate(args_index):
                if "*" in v and not i == kwarg_index:
                    arg_index = i

            if arg_index:
                if not send_request:
                    params.insert(0, request_parameter)
                params.insert(arg_index - 1, token_parameter)
            elif not kwarg_index:
                if not send_request:
                    params.insert(0, request_parameter)
                params.append(token_parameter)
            ## ** kwargs
            else:
                if not send_request:
                    params.insert(0, request_parameter)
                params.insert(kwarg_index - 1, token_parameter)

            new_sig = func_sig.replace(parameters=params)

            @wraps(func, new_sig=new_sig)
            async def mock_function(*args, **kwargs):
                request = kwargs["request"]
                token = kwargs["token"]
                if token == "NO_TOKEN" or token == "INVALID":
                    if (
                        response_class is HTMLResponse
                        or "text/html" in request.headers["accept"]
                    ):
                        response = HTMLResponse(
                            await self.parent.get_login_page(
                                message="Login Required", request=request
                            ),
                            status_code=401,
                        )
                        response.set_cookie(
                            "token", "INVALID", **self.parent.cookie_security
                        )
                        response.set_cookie(
                            "ref",
                            request.__dict__["scope"]["path"],
                            **self.parent.cookie_security,
                        )
                        return response
                try:
                    token = self.parent.decode_token(token)[1]
                except Exception:
                    self.parent.log.exception(f"error decoding token")
                    if (
                        response_class is HTMLResponse
                        or "text/html" in request.headers["accept"]
                    ):
                        response = HTMLResponse(
                            await self.parent.get_login_page(
                                message="Login Required", request=request
                            ),
                            status_code=401,
                        )
                        response.set_cookie(
                            "token", "INVALID", **self.parent.cookie_security
                        )
                        response.headers["ref"] = request.__dict__["scope"]["path"]
                        return response
                    raise HTTPException(
                        status_code=401, detail=f"not authorized, invalid or expired"
                    )

                allowed = False
                for auth_type, values in permissions.items():
                    if not auth_type in token["permissions"]:
                        self.parent.log.warning(f"{auth_type} is required")
                        continue
                    for value in values:
                        if value in token["permissions"][auth_type]:
                            allowed = True
                            break
                if not token["token_id"] in self.parent.store["tokens"]:
                    self.log.error(
                        f"token for user {token['permissions']['users'][0]} - {token['token_id']} is unknown / revoked {self.parent.store['tokens']}"
                    )
                    allowed = False

                if not allowed:
                    if (
                        response_class is HTMLResponse
                        or "text/html" in request.headers["accept"]
                    ):
                        response = HTMLResponse(
                            await self.parent.get_403_page(), status_code=403
                        )

                        return response
                    raise HTTPException(
                        status_code=403,
                        detail=f"not authorized, permissions required: {permissions}",
                    )

                if "access_token" in kwargs:
                    kwargs["access_token"] = token

                if not send_token:
                    del kwargs["token"]
                if not send_request:
                    del kwargs["request"]

                result = func(*args, **kwargs)
                if asyncio.iscoroutine(result):
                    return await result
                return result

            mock_function.__name__ = func.__name__

            route = getattr(self.server, method)

            route(path, *args, **kwargs)(mock_function)
            return mock_function

        return auth_endpoint

    def get(
        self,
        path,
        users: list = None,
        groups: list = None,
        roles: list = None,
        actions: list = None,
        send_token: bool = False,
        *args,
        **kwargs,
    ):
        permissions = self.parent.parse_permissions(
            users, groups, roles, actions, self.default_permissions
        )
        return self.router(
            path, "get", permissions=permissions, send_token=send_token, *args, **kwargs
        )

    def post(
        self,
        path,
        users: list = None,
        groups: list = None,
        roles: list = None,
        actions: list = None,
        send_token: bool = False,
        *args,
        **kwargs,
    ):
        permissions = self.parent.parse_permissions(
            users, groups, roles, actions, self.default_permissions
        )
        return self.router(
            path,
            "post",
            permissions=permissions,
            send_token=send_token,
            *args,
            **kwargs,
        )

    def update(
        self,
        path,
        users: list = None,
        groups: list = None,
        roles: list = None,
        actions: list = None,
        send_token: bool = False,
        *args,
        **kwargs,
    ):
        permissions = self.parent.parse_permissions(
            users, groups, roles, actions, self.default_permissions
        )
        return self.router(
            path,
            "udpate",
            permissions=permissions,
            send_token=send_token,
            *args,
            **kwargs,
        )

    def delete(
        self,
        path,
        users: list = None,
        groups: list = None,
        roles: list = None,
        actions: list = None,
        send_token: bool = False,
        *args,
        **kwargs,
    ):
        permissions = self.parent.parse_permissions(
            users, groups, roles, actions, self.default_permissions
        )
        return self.router(
            path,
            "delete",
            permissions=permissions,
            send_token=send_token,
            *args,
            **kwargs,
        )

    def put(
        self,
        path,
        users: list = None,
        groups: list = None,
        roles: list = None,
        actions: list = None,
        send_token: bool = False,
        *args,
        **kwargs,
    ):
        permissions = self.parent.parse_permissions(
            users, groups, roles, actions, self.default_permissions
        )
        return self.router(
            path, "put", permissions=permissions, send_token=send_token, *args, **kwargs
        )

    def patch(
        self,
        path,
        users: list = None,
        groups: list = None,
        roles: list = None,
        actions: list = None,
        send_token: bool = False,
        *args,
        **kwargs,
    ):
        permissions = self.parent.parse_permissions(
            users, groups, roles, actions, self.default_permissions
        )
        return self.router(
            path,
            "patch",
            permissions=permissions,
            send_token=send_token,
            *args,
            **kwargs,
        )

    def options(
        self,
        path,
        users: list = None,
        groups: list = None,
        roles: list = None,
        actions: list = None,
        send_token: bool = False,
        *args,
        **kwargs,
    ):
        permissions = self.parent.parse_permissions(
            users, groups, roles, actions, self.default_permissions
        )
        return self.router(
            path,
            "options",
            permissions=permissions,
            send_token=send_token,
            *args,
            **kwargs,
        )

    def head(
        self,
        path,
        users: list = None,
        groups: list = None,
        roles: list = None,
        actions: list = None,
        send_token: bool = False,
        *args,
        **kwargs,
    ):
        permissions = self.parent.parse_permissions(
            users, groups, roles, actions, self.default_permissions
        )
        return self.router(
            path,
            "head",
            permissions=permissions,
            send_token=send_token,
            *args,
            **kwargs,
        )
