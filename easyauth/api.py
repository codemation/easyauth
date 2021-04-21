from typing import Optional, List, Union
from pydantic import BaseModel
from starlette.status import HTTP_302_FOUND
from fastapi import HTTPException, Depends, Form, Response, Request
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.security import OAuth2PasswordRequestForm
from easyauth.models import User, Service, Group, Role, Permission
from aiohttp import ClientSession


async def api_setup(server):

    class Token(BaseModel):
        access_token: str
        token_type: str

    users_tb = server.auth_users
    groups_tb = server.auth_groups
    roles_tb = server.auth_roles
    permissions_tb = server.auth_actions

    async def verify_user(user):
        if await users_tb[user] is None:
            # raise group does not exist
            raise HTTPException(status_code=404, detail=f"no user with name {user} exists")
    async def verify_group(group):
        if await groups_tb[group] is None:
            # raise group does not exist
            raise HTTPException(status_code=404, detail=f"no group with name {group} exists, create first")
    async def verify_role(role):
        if await roles_tb[role] is None:
            # raise group does not exist
            raise HTTPException(status_code=404, detail=f"no role with name {role} exists, create first")
    async def verify_action(action):
        if await permissions_tb[action] is None:
            # raise group does not exist
            raise HTTPException(status_code=404, detail=f"no action with name {action} exists, create first")
    
    @server.get('/auth/export', tags=['Config'])
    async def export_auth_config():
        return {
            'users': await users_tb.select('*'),
            'groups': await groups_tb.select('*'),
            'roles': await roles_tb.select('*'),
            'actions': await permissions_tb.select('*')
        }
    
    class Config(BaseModel):
        users: Optional[List[User]]
        groups: Optional[List[Group]]
        roles: Optional[List[Role]]
        actions: Optional[List[Permission]]


    @server.post('/auth/import', tags=['Config'])
    async def import_auth_config(config: Config):
        config = dict(config)
        if 'actions' in config:
            for action in config['actions']:
                action = dict(action)
                try:
                    await verify_action(action['action'])
                    await server.auth_actions.update(
                        where={'action': action.pop('action')},
                        **action
                    )
                except Exception:
                    await server.auth_actions.insert(**action)

        if 'roles' in config:
            for role in config['roles']:
                role = dict(role)
                for action in role['permissions']['actions']:
                    await verify_action(action)
                try:
                    await verify_role(role['role'])
                except Exception:
                    await server.auth_roles.insert(**role)
                    continue
                await server.auth_roles.update(
                    where={'role': role.pop('role')},
                    **role
                )
        
        if 'groups' in config:
            for group in config['groups']:
                group = dict(group)
                for role_name in group['roles']['roles']:
                    await verify_role(role_name)
                try:
                    await verify_group(group['group_name'])
                except Exception:
                    await server.auth_groups.insert(**group)
                    continue
                await server.auth_groups.update(
                    where={'group_name': group.pop('group_name')},
                    **group
                )

        if 'users' in config:
            for user in config['users']:
                user = dict(user)
                if 'groups' in user:
                    for group_name in user['groups']['groups']:
                        await verify_group(group_name)
                try:
                    await verify_user(user['username'])
                except Exception:
                    await server.auth_users.insert(**user)
                    continue

                await server.auth_users.update(
                    where={'username': user.pop('username')},
                    **user
                )
        return f"import_auth_config - completed"

    @server.get('/auth/serviceaccount/token/{service}', response_model=Token, tags=['Token'])
    async def get_service_account_token(service: str):
        service_user = await users_tb[service]
        if service_user is None:
            raise HTTPException(status_code=404, detail=f"no service user with name {service} exists")

        if not service_user['account_type'] == 'service':
            raise HTTPException(status_code=400, detail=f"user {service} is not a service type account")
        permissions = await server.get_user_permissions(service)

        token = server.issue_token(permissions, days=999)

        server.log.warning(f"token generated: {type(token)}")
        return {
            "access_token": token, 
            "token_type": "bearer"
        }
    @server.server.post('/auth/token/refresh', response_model=Token, tags=['Token'])
    async def refresh_access_token(token: str = Depends(server.oauth2_scheme)):
        try:
            token = server.decode_token(token)[1]
            user_in_token = token['permissions']['users'][0]
            user = await server.db.tables['users'].select('*', where={'username': user_in_token})
            server.log.warning(f"refresh_access_token: called for user: {user[0]}")
            # get user permissions
            permissions = await server.get_user_permissions(user_in_token)

            # generate RSA token
            token = server.issue_token(permissions)
            server.log.warning(f"token generated: {type(token)}")
            return {
                "access_token": token, 
                "token_type": "bearer"
            }

            return token
        except Exception:
            server.log.exception(f"refresh_access_token error")
            raise HTTPException(
                status_code=401, 
                detail="token is invalid or expired"
            )

    @server.server.post('/auth/token/login', response_model=Token, tags=['Token'])
    async def login_for_auth_token(authentication: dict):
        username = authentication.get('username')
        password = authentication.get('password')
        if not username or not password:
            raise HTTPException(
                status_code=401, 
                detail="unable to authenticate with provided credentials"
            )
        user = await server.validate_user_pw(username, password)
        if user:
            permissions = await server.get_user_permissions(user[0]['username'])
            token = server.issue_token(permissions)
            server.log.warning(f"token generated: {type(token)}")
            return {
                "access_token": token, 
                "token_type": "bearer"
            }
        raise HTTPException(
            detail=f"invalid username / password", status_code=401
        )
        

    @server.server.post('/auth/token', response_model=Token, tags=['Token'])
    async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
        server.log.debug(f"login_for_access_token: form_data {form_data}")
        user = await server.validate_user_pw(form_data.username, form_data.password)
        if not user:
            raise HTTPException(
                status_code=401, 
                detail="unable to authenticate with provided credentials"
            )
        # get user permissions
        permissions = await server.get_user_permissions(form_data.username)

        # generate RSA token
        token = server.issue_token(permissions)
        server.log.warning(f"token generated: {type(token)}")
        return {
            "access_token": token, 
            "token_type": "bearer"
        }

    @server.server.get("/login/re", tags=['Login'], response_class=HTMLResponse, include_in_schema=False)
    async def login_redirect_get(response: Response):
        return server.admin.login_page(welcome_message='Login Required')

    @server.server.post("/login/re", tags=['Login'], response_class=HTMLResponse, include_in_schema=False)
    async def login_redirect(response: Response):
        return server.admin.login_page(welcome_message='Login Required')

    @server.server.post("/login", tags=['Login'], response_class=HTMLResponse, include_in_schema=False)
    async def login_page(
        request: Request,
        response: Response,
        username: str = Form(...), 
        password: str = Form(...),
    ):
        server.log.warning(f"login_page {username}")
        user = await server.validate_user_pw(username, password)
        
        if not user:
            return server.admin.login_page(welcome_message="logged out - Login Required")
            raise HTTPException(
                status_code=401, 
                detail="unable to authenticate with provided credentials"
            )

        # get user permissions
        permissions = await server.get_user_permissions(username)

        token = server.issue_token(permissions)

        # add token to cookie
        response.set_cookie('token', token)
        redirect_ref = '/'

        if 'ref' in request.cookies:
            redirect_ref = request.cookies['ref']
            response.delete_cookie('ref')

        return RedirectResponse(redirect_ref, headers=response.headers, status_code=HTTP_302_FOUND)
    @server.server.get("/logout", tags=['Login'], response_class=HTMLResponse)
    async def logout_page(
        response: Response
    ):
        response.set_cookie('token', 'INVALID')
        return RedirectResponse('/login', headers=response.headers)

    @server.server.post("/logout", tags=['Login'], response_class=HTMLResponse)
    async def logout_page_post(
        response: Response,
    ):
        response.set_cookie('token', 'INVALID')
        return RedirectResponse('/login/re', headers=response.headers)

    @server.put('/auth/user', status_code=201, tags=['Users'])
    async def create_user(user: User):
        user = dict(user)

        # list -> dict conversion for db storage
        if isinstance(user['groups'], list):
            user['groups'] = {'groups': user['groups']}

        if not await users_tb[user['username']] is None:
            raise HTTPException(status_code=400, detail=f"{user['username']} already exists")
        for group in user['groups']['groups']:
            await verify_group(group)

        # encode password before storing
        user['password'] = server.encode_password(user['password'])
        user['account_type'] = 'user'

        await users_tb.insert(**user)

        # trigger some activation email later?
        return f"{user['username']} created"
        
    @server.put('/auth/service', status_code=201, actions=['CREATE_USER'], tags=['Users'])
    async def create_service(service: Service):
        service = dict(service)

        # list -> dict conversion for db storage
        if isinstance(service['groups'], list):
            service['groups'] = {'groups': service['groups']}

        if not await users_tb[service['username']] is None:
            raise HTTPException(status_code=400, detail=f"{service['username']} already exists")

        for group in service['groups']['groups']:
            await verify_group(group)
        
        service['account_type'] = 'service'

        await users_tb.insert(**service)
        # trigger some activation email later?

        return f"{service['username']} created"

    class UserGroup(BaseModel):
        groups: list

    class UserUpdate(BaseModel):
        full_name: Optional[str]
        password: Optional[str]
        email: Optional[str]
        groups: Optional[Union[list, UserGroup]]

    @server.post('/auth/user/{username}', tags=['Users'])
    async def update_user(
        username: str,
        update: UserUpdate
    ):
        await verify_user(username)
        
        update = {k: v for k, v in dict(update).items() if not v is None}

        to_update = {}
        for k, v in update.copy().items():
            if k == 'groups':
                if isinstance(v, list):
                    update[k] = {'groups': v}

                to_update[k] = update[k]
                for group in to_update[k]['groups']:
                    await verify_group(group)
            else:
                to_update[k] = v
                
        server.log.warning(f"update: {to_update}")
        update = to_update

        if "password" in update:
            # encode password before storing
            update['password'] = server.encode_password(update['password'])

        await users_tb.update(
            where={'username': username},
            **update
        )
        return f"{username} updated"

    @server.delete('/auth/user', tags=['Users'])
    async def delete_user(username: str):
        await verify_user(username)
        await users_tb.delete(where={'username': username})
        return f"{username} deleted"

    @server.get('/auth/users', tags=['Users'])
    async def get_all_users():
        return await users_tb.select('*')

    @server.get('/auth/users/{username}', tags=['Users'])
    async def get_user(username: str):
        return await get_user_details(username)

    async def get_user_details(username: str):
        await verify_user(username)
        user = await users_tb[username]
        user = user.copy()
        permissions = await server.get_user_permissions(username)
        user['permissions'] = permissions
        return user
        
    server.get_user_details = get_user_details

    # Groups

    @server.put('/auth/group', status_code=201, tags=['Groups'])
    async def create_group(group: Group):
        group = dict(group)
    
        # list -> dict conversion for db storage
        if isinstance(group['roles'], list):
            group['roles'] = {'roles': group['roles']}

        if not await groups_tb[group['group_name']] is None:
            raise HTTPException(status_code=400, detail=f"{group['group_name']} already exists")

        for role in group['roles']['roles']:
            await verify_role(role)

        await groups_tb.insert(**group)
        return f"group {group['group_name']} created"

    class UpdateRoles(BaseModel):
        roles: list

    @server.post('/auth/group/{group}', status_code=201, tags=['Groups'])
    async def update_group(group: str, roles: UpdateRoles):
        roles = dict(roles)
        await verify_group(group)
        for role in roles['roles']:
            await verify_role(role)
        await groups_tb.update(
            roles={'roles': roles['roles']},
            where={'group_name': group}
        )
        return f"existing group updated"
        
    @server.delete('/auth/group', tags=['Groups'])
    async def delete_group(group_name: str):
        await verify_group(group_name)
        await groups_tb.delete(where={'group_name': group_name})
        return f"{group_name} deleted"

    @server.get('/auth/groups', tags=['Groups'])
    async def get_all_groups():
        return await groups_tb.select('*')

    @server.get('/auth/groups/{group}', tags=['Groups'])
    async def get_group(group_name: str):
        await verify_group(group_name)
        group = await groups_tb[group_name]
        return group

    # Roles

    @server.put('/auth/role', status_code=201, tags=['Roles'])
    async def create_role(role: Role):
        role = dict(role)

        # list -> dict conversion for db storage
        if isinstance(role['permissions'], list):
            role['permissions'] = {'actions': role['permissions']}

        if not await roles_tb[role['role']] is None:
            raise HTTPException(status_code=400, detail=f"{role['role']} already exists")
        
        for permission in role['permissions']['actions']:
            await verify_action(permission)
        
        await roles_tb.insert(**role)
        return f"role {role['role']} created"

    class UpdateActions(BaseModel):
        actions: list

    @server.post('/auth/role/{role}', status_code=201, tags=['Roles'])
    async def update_role(role: str, actions: UpdateActions):
        actions = dict(actions)
        await verify_role(role)
        for action in actions['actions']:
            await verify_action(action)

        await roles_tb.update(
            permissions={'actions': actions['actions']},
            where={'role': role}
        )
        return f"existing role updated"

    @server.delete('/auth/role', tags=['Roles'])
    async def delete_role(role: str):
        await verify_role(role)
        await roles_tb.delete(where={'role': role})
        return f"{role} deleted"

    @server.get('/auth/roles', tags=['Roles'])
    async def get_all_roles():
        return await roles_tb.select('*')

    @server.get('/auth/roles/{role}', tags=['Roles'])
    async def get_role(role: str):
        await verify_role(role)
        role = await roles_tb[role]
        return role

    ## Permissions 

    @server.put('/auth/permissions', status_code=201, tags=['Actions'])
    async def create_permission(permission: Permission):
        permission = dict(permission)
        if not await permissions_tb[permission['action']] is None:
            raise HTTPException(status_code=400, detail=f"{permission['action']} already exists")

        await permissions_tb.insert(**permission)
        return f"permission {permission['action']} created"

    class UpdateDetails(BaseModel):
        detail: str

    @server.post('/auth/permissions', status_code=201, tags=['Actions'])
    async def update_permission(action: str, detail: UpdateDetails):
        detail = dict(detail)
        await verify_action(action)
        await permissions_tb.update(
            details=detail['detail'],
            where={'action': action},
        )
        return f"existing permission updated"

    @server.delete('/auth/permission', tags=['Actions'])
    async def delete_permission(action):
        await verify_action(action)
        await permissions_tb.delete(where={'action': action})
        return f"{action} deleted"

    @server.get('/auth/permissions', tags=['Actions'])
    async def get_all_permissons():
        return await permissions_tb.select('*')

    @server.get('/auth/permission/{action}', tags=['Actions'])
    async def get_permission(action: str):
        await verify_action(action)
        permission = await permissions_tb[action]
        return permission