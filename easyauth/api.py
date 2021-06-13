from typing import Optional, List, Union
from pydantic import BaseModel, ValidationError
from starlette.status import HTTP_302_FOUND
from fastapi import HTTPException, Depends, Form, Response, Request
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.security import OAuth2PasswordRequestForm
from easyauth.models import (
    User, RegisterUser, 
    Service, Group, 
    Role, Permission, 
    EmailConfig, Email,
    EmailSetup, ActivationCode,
    OauthConfig
)
from easyauth.exceptions import (
    DuplicateUserError,
    InvalidActivationCode,
    InvalidUsernameOrPassword
)
from easyadmin.elements import card

async def api_setup(server):

    class Token(BaseModel):
        access_token: str
        token_type: str
    
    api_router = server.api_routers[0]
    admin_gui = server.api_routers[0]

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
    
    @api_router.get('/auth/export', tags=['Config'])
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


    @api_router.post('/auth/import', tags=['Config'])
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

    @api_router.get('/auth/serviceaccount/token/{service}', response_model=Token, tags=['Token'])
    async def get_service_account_token(service: str):
        service_user = await users_tb[service]
        if service_user is None:
            raise HTTPException(status_code=404, detail=f"no service user with name {service} exists")

        if not service_user['account_type'] == 'service':
            raise HTTPException(status_code=400, detail=f"user {service} is not a service type account")
        permissions = await server.get_user_permissions(service)

        token = await server.issue_token(permissions, days=999)

        server.log.warning(f"token generated: {type(token)}")
        return {
            "access_token": token, 
            "token_type": "bearer"
        }
    @server.server.delete('/auth/token', tags=['Token'])
    async def revoke_access_token(token_id: str):
        await server.revoke_token(token_id)
        return f"token revoked"
    

    @api_router.get('/auth/oauth')
    async def get_oauth_providers():
        return await server.db.tables['oauth'].select(
            '*',
        )

    @api_router.post('/auth/oauth/{provider}')
    async def configure_oauth_provider(provider: str, config: Union[OauthConfig, dict]):
        # check for existing config
        config = config.dict() if not isinstance(config, dict) else config
        oauth_config = await server.db.tables['oauth'].select(
            '*',
            where={
                'provider': provider
            }
        )
        if oauth_config:
            # update
            await server.db.tables['oauth'].update(
                client_id=config['client_id'],
                enabled='enabled' in config['enabled'],
                default_groups={'default_groups': config['default_groups']},
                where={'provider': provider}
            )
            return f"{provider} OAuth Configured"
        await server.db.tables['oauth'].insert(
            provider=provider,
            client_id=config['client_id'],
            enabled='enabled' in config['enabled'],
            default_groups={'default_groups': config['default_groups']}
        )
        return f"{provider} OAuth Configured"

    @server.server.post('/auth/token/oauth/google', include_in_schema=False)
    async def create_google_oauth_token_api(request: Request, response: Response):
        token = await server.generate_google_oauth_token(request)
        # add token to cookie
        response.set_cookie('token', token)

        redirect_ref = server.ADMIN_PREFIX

        if 'ref' in request.cookies:
            redirect_ref = request.cookies['ref']
            response.delete_cookie('ref')

        return RedirectResponse(redirect_ref, headers=response.headers, status_code=HTTP_302_FOUND)


    @server.server.post('/auth/token/refresh', response_model=Token, tags=['Token'])
    async def refresh_access_token(token: str = Depends(server.oauth2_scheme)):
        try:
            token = server.decode_token(token)[1]
            user_in_token = token['permissions']['users'][0]
            user = await server.auth_users.select('*', where={'username': user_in_token})
            server.log.warning(f"refresh_access_token: called for user: {user[0]}")
            # get user permissions
            permissions = await server.get_user_permissions(user_in_token)

            # generate RSA token
            token = await server.issue_token(permissions)
            server.log.warning(f"token generated: {type(token)}")
            return {
                "access_token": token, 
                "token_type": "bearer"
            }

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
        return await generate_auth_token(username, password)

    @server.rpc_server.origin(namespace='easyauth')
    async def generate_auth_token(username: str, password: str):

        user = await server.validate_user_pw(username, password)
        if user:
            permissions = await server.get_user_permissions(user[0]['username'])
            token = await server.issue_token(permissions)
            server.log.warning(f"token generated: {type(token)}")
            return {
                "access_token": token, 
                "token_type": "bearer"
            }
        raise InvalidUsernameOrPassword
    server.generate_auth_token = generate_auth_token

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
        token = await server.issue_token(permissions)
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
            return await server.get_login_page(
                message="logged out - Login Required",
                request=request
            )

        # get user permissions
        permissions = await server.get_user_permissions(username)
        token = await server.issue_token(permissions)

        # add token to cookie
        response.set_cookie('token', token)

        redirect_ref = server.ADMIN_PREFIX

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

    @server.server.post("/auth/user/activate")
    async def activate_user_api(activation_code: ActivationCode):
        return await activate_user(activation_code)

    @server.rpc_server.origin(namespace='easyauth')
    async def activate_user(activation_code: dict):
        activation_code = ActivationCode(**activation_code)
        code = activation_code.activation_code

        # verify activation code
        new_user = await server.db.tables['pending_users'].select(
            '*',
            where={'activation_code': code}
        )
        if not new_user:
            raise InvalidActivationCode()
        
        user_info = new_user[0]['user_info']

        # decode
        user_info = server.decode(user_info)[1]['user_info']

        user = User(
            username=user_info['username'],
            password=user_info['password'],
            full_name=user_info['full name'],
            email=user_info['email address']
        )

        result = await __create_user(user)
        server.log.warning(f"user {user_info['username']} created after successful activation")
        return f"{user_info['username']} activated"


    @server.server.post("/auth/user/register")
    async def register_user_api(user_info: dict):
        return await register_user(user_info)

    @server.rpc_server.origin(namespace='easyauth')
    async def register_user(user_info: dict):
        """
        registers a new user, if email is configured & enabled 
        sends activation email for user. 
        """
        # check default groups assignment
        if not 'groups' in user_info or not user_info['groups']:
            default_groups = await server.db.tables['oauth'].select(
                '*',
                where={'provider': 'easyauth'}
            )
            if default_groups[0]['default_groups']['default_groups']:
                if default_groups[0]['enabled']:
                    user_info['groups'] = default_groups[0]['default_groups']['default_groups']

        try:
            register_user = RegisterUser(
                username=user_info['username'],
                full_name=user_info['full name'],
                password1=user_info['password'],
                password2=user_info['repeat password'],
                email=user_info['email address']
            )
            user = User(
                username=user_info['username'],
                password=user_info['password'],
                full_name=user_info['full name'],
                email=user_info['email address'],
                groups=user_info['groups'] if 'groups' in user_info else []
            )
        except ValueError as e:
            raise HTTPException(
                status_code=422,
                detail=repr(e)
            )
        
        # check for duplicate user
        duplicate = await server.db.tables['users'].select(
            'username', 
            where={'username': user_info['username']}
        )
        if duplicate:
            raise DuplicateUserError(duplicate[0]['username'])

        email = await server.db.tables['email_config'].select('*')
        if email and email[0]['send_activation_emails']:

            # generate activation code
            activation_code = server.generate_random_string(16)

            # encrypt user details with activation code & store
            encoded_data = server.encode(user_info=user_info)

            # insert into unactivated users

            result = await server.db.tables['pending_users'].insert(
                activation_code=activation_code,
                user_info=encoded_data
            )

            # send activation code to email
            await server.send_email(
                "New User Activation",
                f"New User Activation Code: {activation_code}",
                user_info['email address'],
            )
            return f"Activation email sent to {user_info['email address']}"
        return await __create_user(user)
    server.register_user = register_user

    @api_router.put('/auth/user', status_code=201, tags=['Users'])
    async def create_user(user: User):
        return await __create_user(user)
        
    async def __create_user(user: User):
        user = dict(user)

        if not user['groups']:
            user['groups'] = []

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
    
    server.create_user = __create_user
        
    @api_router.put('/auth/service', status_code=201, actions=['CREATE_USER'], tags=['Users'])
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

    @api_router.post('/auth/user/{username}', tags=['Users'])
    async def update_user(
        username: str,
        update: UserUpdate
    ):
        await verify_user(username)
        
        update = {k: v for k, v in dict(update).items() if not v is None}

        to_update = {}
        for k, v in update.copy().items():
            if v == '':
                continue
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

    @api_router.delete('/auth/user', tags=['Users'])
    async def delete_user(username: str):
        await verify_user(username)
        await users_tb.delete(where={'username': username})
        return f"{username} deleted"

    @api_router.get('/auth/users', tags=['Users'])
    async def get_all_users():
        return await users_tb.select('*')

    @api_router.get('/auth/users/{username}', tags=['Users'])
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

    @api_router.put('/auth/group', status_code=201, tags=['Groups'])
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

    @api_router.post('/auth/group/{group}', status_code=200, tags=['Groups'])
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
        
    @api_router.delete('/auth/group', tags=['Groups'])
    async def delete_group(group_name: str):
        await verify_group(group_name)
        await groups_tb.delete(where={'group_name': group_name})
        return f"{group_name} deleted"

    @api_router.get('/auth/groups', tags=['Groups'])
    async def get_all_groups():
        return await groups_tb.select('*')

    @api_router.get('/auth/groups/{group_name}', tags=['Groups'])
    async def get_group(group_name: str):
        await verify_group(group_name)
        group = await groups_tb[group_name]
        return group

    # Roles

    @api_router.put('/auth/role', status_code=201, tags=['Roles'])
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

    @api_router.post('/auth/role/{role}', status_code=200, tags=['Roles'])
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

    @api_router.delete('/auth/role', tags=['Roles'])
    async def delete_role(role: str):
        await verify_role(role)
        await roles_tb.delete(where={'role': role})
        return f"{role} deleted"

    @api_router.get('/auth/roles', tags=['Roles'])
    async def get_all_roles():
        return await roles_tb.select('*')

    @api_router.get('/auth/roles/{role}', tags=['Roles'])
    async def get_role(role: str):
        await verify_role(role)
        role = await roles_tb[role]
        return role

    ## Permissions 

    @api_router.put('/auth/permissions', status_code=201, tags=['Actions'])
    async def create_permission(permission: Permission):
        permission = dict(permission)
        if not await permissions_tb[permission['action']] is None:
            raise HTTPException(status_code=400, detail=f"{permission['action']} already exists")

        await permissions_tb.insert(**permission)
        return f"permission {permission['action']} created"

    class UpdateDetails(BaseModel):
        detail: str

    @api_router.post('/auth/permissions', status_code=200, tags=['Actions'])
    async def update_permission(action: str, detail: UpdateDetails):
        detail = dict(detail)
        await verify_action(action)
        await permissions_tb.update(
            details=detail['detail'],
            where={'action': action},
        )
        return f"existing permission updated"

    @api_router.delete('/auth/permission', tags=['Actions'])
    async def delete_permission(action):
        await verify_action(action)
        await permissions_tb.delete(where={'action': action})
        return f"{action} deleted"

    @api_router.get('/auth/permissions', tags=['Actions'])
    async def get_all_permissons():
        return await permissions_tb.select('*')

    @api_router.get('/auth/permission/{action}', tags=['Actions'])
    async def get_permission(action: str):
        await verify_action(action)
        permission = await permissions_tb[action]
        return permission
    

    ## Email API

    @api_router.get('/email/config', tags=['Email'])
    async def get_email_configuration():
        return await server.get_email_config()

    @api_router.post('/email/setup', tags=['Email'])
    async def setup_email_cofiguration(config: EmailSetup):
        return await server.email_setup(
            username=config.MAIL_USERNAME,
            password=config.MAIL_PASSWORD,
            mail_from=config.MAIL_FROM,
            mail_from_name=config.MAIL_FROM,
            server=config.MAIL_SERVER,
            port=config.MAIL_PORT,
            mail_tls='MAIL_TLS' in config.MAIL_TLS,
            mail_ssl='MAIL_SSL' in config.MAIL_SSL,
            send_activation_emails='SEND_ACTIVATION_EMAILS' in config.SEND_ACTIVATION_EMAILS
        )
    @api_router.post('/email/send', tags=['Email'])
    async def send_email(email: Email, test_email: bool = False):
        return await server.send_email(
            subject=email.subject,
            email=email.email_body,
            recipients=email.recipients,
            test_email=test_email
        )