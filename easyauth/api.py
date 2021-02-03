from pydantic import BaseModel
from fastapi import HTTPException, Depends
from fastapi.security import OAuth2PasswordRequestForm

from easyauth.models import User, Group, Role, Permission


async def api_setup(server):

    class Token(BaseModel):
        access_token: str
        token_type: str

    users_tb = server.db.tables['users']
    groups_tb = server.db.tables['groups']
    roles_tb = server.db.tables['roles']
    permissions_tb = server.db.tables['permissions']

    @server.get('/auth/serviceaccount/token/{service}', response_model=Token, tags=['Token'])
    async def get_service_account_token(service: str):
        service_user = await users_tb[service]
        if service_user is None:
            raise HTTPException(status_code=404, detail=f"no service user with name {service} exists")

        if not service_user['account_type'] == 'service':
            raise HTTPException(status_code=400, detail=f"user {service} is not a service type account")
        print(service_user)
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
            if await groups_tb[group] is None:
                # raise group does not exist
                raise HTTPException(status_code=400, detail=f"no group with name {group} exists, create first")

        # encode password before storing
        user['password'] = server.encode_password(user['password'])

        await users_tb.insert(**user)

        # trigger some activation email later?

        return f"{user['username']} created"

    @server.post('/auth/users', status_code=201, tags=['Users'])
    async def create_or_update_user(user: User):
        user = dict(user)
        if "password" in user:
            # encode password before storing
            user['password'] = server.encode_password(user['password']) 
        if not await users_tb[user['username']] is None:

            await users_tb.update(
                where={'username': user.pop('username')},
                **user
            )
            return f"existing user updated"    

        await users_tb.insert(**user)
        return f"user {role['username']} created"

    @server.delete('/auth/user', tags=['Users'])
    async def delete_user(username: str):
        if await users_tb[username] is None:
            raise HTTPException(status_code=404, detail=f"no user found with name {username}")
        await users_tb.delete(where={'username': username})
        return f"{username} deleted"

    @server.get('/auth/users', tags=['Users'])
    async def get_all_users():
        return await users_tb.select('*')

    @server.get('/auth/users/{user}', tags=['Users'])
    async def get_user(username: str):
        user = await users_tb[username]
        if user is None:
            raise HTTPException(status_code=404, detail=f"no user found with name {username}")
        return user


    # Groups

    @server.put('/auth/group', status_code=201, tags=['Groups'])
    async def create_group(group: Group):
        group = dict(group)

        if not await groups_tb[group['group_name']] is None:
            raise HTTPException(status_code=400, detail=f"{group['group_name']} already exists")

        for role in group['roles']['roles']:
            if await groups_tb[role] is None:
                # raise group does not exist
                raise HTTPException(status_code=400, detail=f"no role with name {role} exists, create first")

        await groups_tb.insert(**group)
        return f"group {group['group_name']} created"


    @server.post('/auth/groups', status_code=201, tags=['Groups'])
    async def create_or_update_group(group: Group):
        group = dict(group)
        if not await groups_tb[group['group_name']] is None:
            await groups_tb.update(
                where={'group_name': group.pop('group_name')},
                **group
            )
            return f"existing group updated"

        await groups_tb.insert(**group)
        return f"group {group['group_name']} created"
        
    @server.delete('/auth/group', tags=['Groups'])
    async def delete_group(group_name):
        if await groups_tb[group_name] is None:
            raise HTTPException(status_code=404, detail=f"no group found with name {group_name}")
        await groups_tb.delete(where={'group_name': group_name})
        return f"{group_name} deleted"

    @server.get('/auth/groups', tags=['Groups'])
    async def get_all_groups():
        return await groups_tb.select('*')

    @server.get('/auth/groups/{group}', tags=['Groups'])
    async def get_group(group_name: str):
        group = await groups_tb[group_name]
        if group is None:
            raise HTTPException(status_code=404, detail=f"no group found with name {group_name}")
        return group


    # Roles

    @server.put('/auth/role', status_code=201, tags=['Roles'])
    async def create_role(role: Role):
        role = dict(role)

        if not await roles_tb[role['role']] is None:
            raise HTTPException(status_code=400, detail=f"{role['role']} already exists")
        
        for permission in role['permissions']['actions']:
            exists = await permissions_tb[permission]
            print(exists)
            if await permissions_tb[permission] is None:
                # raise group does not exist
                raise HTTPException(status_code=400, detail=f"no permission with name {permission} exists, create first")
        
        await roles_tb.insert(**role)
        return f"role {role['role']} created"

    @server.post('/auth/roles', status_code=201, tags=['Roles'])
    async def create_or_update_role(role: Role):
        role = dict(role)
        if not await roles_tb[role['role']] is None:
            await roles_tb.update(
                where={'role': role.pop('role')},
                **role
            )
            return f"existing role updated"

        await roles_tb.insert(**role)
        return f"role {role['role']} created"

    @server.delete('/auth/role', tags=['Roles'])
    async def delete_role(role):
        if await roles_tb[action] is None:
            raise HTTPException(status_code=404, detail=f"no role found with name {role}")
        await roles_tb.delete(where={'role': role})
        return f"{role} deleted"

    @server.get('/auth/roles', tags=['Roles'])
    async def get_all_roles():
        return await roles_tb.select('*')

    @server.get('/auth/roles/{role}', tags=['Roles'])
    async def get_role(role: str):
        role = await roles_tb[role]
        if role is None:
            raise HTTPException(status_code=404, detail=f"no role found with name {role}")
        return role

    
    ## Permissions 

    @server.put('/auth/permissions', status_code=201, tags=['Actions'])
    async def create_permission(permission: Permission):
        permission = dict(permission)
        print(permission)
        if not await permissions_tb[permission['action']] is None:
            raise HTTPException(status_code=400, detail=f"{permission['action']} already exists")

        await permissions_tb.insert(**permission)
        return f"permission {permission['action']} created"

    @server.post('/auth/permissions', status_code=201, tags=['Actions'])
    async def create_or_update_permission(permission: Permission):
        permission = dict(permission)
        print(permission)
        if not await permissions_tb[permission['action']] is None:
            await permissions_tb.update(
                where={'action': permission.pop('action')},
                **permission
            )
            return f"existing permission updated"

        await permissions_tb.insert(**permission)
        return f"permission {permission['action']} created"
    @server.delete('/auth/permission', tags=['Actions'])
    async def delete_permission(action):
        if await permissions_tb[action] is None:
            raise HTTPException(status_code=404, detail=f"not action found with name {action}")
        await permissions_tb.delete(where={'action': action})
        return f"{action} deleted"

    @server.get('/auth/permissions', tags=['Actions'])
    async def get_all_permissons():
        return await permissions_tb.select('*')

    @server.get('/auth/permission/{action}', tags=['Actions'])
    async def get_permission(action: str):
        permission = await permissions_tb[action]
        if permission is None:
            raise HTTPException(status_code=404, detail=f"not action found with name {action}")
        return permission