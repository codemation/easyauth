from typing import Optional
from pydantic import BaseModel
from fastapi import HTTPException, Depends
from fastapi.security import OAuth2PasswordRequestForm

from easyauth.models import User, Service, Group, Role, Permission


async def api_setup(server):

    class Token(BaseModel):
        access_token: str
        token_type: str

    users_tb = server.db.tables['users']
    groups_tb = server.db.tables['groups']
    roles_tb = server.db.tables['roles']
    permissions_tb = server.db.tables['permissions']

    async def verify_user(user):
        if await users_tb[user] is None:
            # raise group does not exist
            raise HTTPException(status_code=400, detail=f"no user with name {user} exists")
    async def verify_group(group):
        if await groups_tb[group] is None:
            # raise group does not exist
            raise HTTPException(status_code=400, detail=f"no group with name {group} exists, create first")
    async def verify_role(role):
        if await roles_tb[role] is None:
            # raise group does not exist
            raise HTTPException(status_code=400, detail=f"no role with name {role} exists, create first")
    async def verify_action(action):
        if await permissions_tb[action] is None:
            # raise group does not exist
            raise HTTPException(status_code=400, detail=f"no action with name {action} exists, create first")


    @server.get('/auth/serviceaccount/token/{service}', response_model=Token, tags=['Token'])
    async def get_service_account_token(service: str):
        service_user = await users_tb[service]
        if service_user is None:
            raise HTTPException(status_code=404, detail=f"no service user with name {service} exists")

        if not service_user['account_type'] == 'service':
            raise HTTPException(status_code=400, detail=f"user {service} is not a service type account")
        permissions = await server.get_user_permissions(service_user)

        token = server.issue_token(permissions, days=999)

        server.log.warning(f"token generated: {type(token)}")
        return {
            "access_token": token, 
            "token_type": "bearer"
        }

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
        permissions = await server.get_user_permissions(user[0])

        # generate RSA token
        token = server.issue_token(permissions)
        server.log.warning(f"token generated: {type(token)}")
        return {
            "access_token": token, 
            "token_type": "bearer"
        }

    @server.put('/auth/user', status_code=201, actions=['CREATE_USER'], tags=['Users'])
    async def create_user(user: User):
        user = dict(user)
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
        groups: Optional[UserGroup]

    @server.post('/auth/user/{username}', tags=['Users'])
    async def update_user(
        username: str,
        update: UserUpdate
    ):
        await verify_user(username)
        
        update = {k: v for k, v in dict(update).items() if not v is None}

        to_update = {}
        for k, v in dict(update).items():
            if k == 'groups':
                to_update[k] = dict(v)
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
        await verify_user(user)
        await users_tb.delete(where={'username': username})
        return f"{username} deleted"

    @server.get('/auth/users', tags=['Users'])
    async def get_all_users():
        return await users_tb.select('*')

    @server.get('/auth/users/{username}', tags=['Users'])
    async def get_user(username: str):
        await verify_user(user)
        user = await users_tb[username]
        return user

    # Groups

    @server.put('/auth/group', status_code=201, tags=['Groups'])
    async def create_group(group: Group):
        group = dict(group)

        if not await groups_tb[group['group_name']] is None:
            raise HTTPException(status_code=400, detail=f"{group['group_name']} already exists")

        for role in group['roles']['roles']:
            await verify_role(role)

        await groups_tb.insert(**group)
        return f"group {group['group_name']} created"

    class UpdateRoles(BaseModel):
        roles: list

    @server.post('/auth/groups', status_code=201, tags=['Groups'])
    async def update_group(group: str, roles: UpdateRoles):
        roles = dict(roles)
        await verify_group(group)
        for role in roles['roles']:
            await verify_role(role)
        await groups_tb.update(
            roles={'roles': roles},
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

        if not await roles_tb[role['role']] is None:
            raise HTTPException(status_code=400, detail=f"{role['role']} already exists")
        
        for permission in role['permissions']['actions']:
            await verify_action(permission)
        
        await roles_tb.insert(**role)
        return f"role {role['role']} created"

    class UpdateActions(BaseModel):
        actions: list

    @server.post('/auth/roles', status_code=201, tags=['Roles'])
    async def update_role(role: str, actions: UpdateActions):
        actions = dict(actions)
        await verify_role(role)
        for action in actions['actions']:
            await verify_action(action)

        await roles_tb.update(
            permissions={'actions': actions},
            where={'role': role.pop('role')}
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