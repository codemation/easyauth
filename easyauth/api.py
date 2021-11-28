import json
from typing import Optional, List
from pydantic import BaseModel
from starlette.status import HTTP_302_FOUND
from fastapi import HTTPException, Depends, Form, Response, Request
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.security import OAuth2PasswordRequestForm
from easyauth.models import (
    Users,
    Services,
    UsersInput,
    Groups,
    GroupsInput,
    Roles,
    RolesInput,
    Actions,
    PendingUsers,
    EmailConfig,
    OauthConfig,
    OauthConfigInput,
    ActivationCode,
    RegisterUser,
    EmailSetup,
    Email
)

from easyauth.exceptions import (
    DuplicateUserError,
    InvalidActivationCode,
    InvalidUsernameOrPassword
)

async def api_setup(server):

    class Token(BaseModel):
        access_token: str
        token_type: str
    
    api_router = server.create_api_router()

    async def verify_user(user):

        user = await Users.get(username=user)
        if not user:
            # raise group does not exist
            raise HTTPException(status_code=404, detail=f"no user with name {user} exists")
        return user

    async def verify_group(group):
        group =  await Groups.get(group_name=group)
        if not group:
            # raise group does not exist
            raise HTTPException(status_code=404, detail=f"no group with name {group} exists, create first")
        return group

    async def verify_role(role):
        role = await Roles.get(role=role)
        if not role:
            # raise group does not exist
            raise HTTPException(status_code=404, detail=f"no role with name {role} exists, create first")
        return role

    async def verify_action(action):
        action = await Actions.get(action=action)
        if not action:
            # raise group does not exist
            raise HTTPException(status_code=404, detail=f"no action with name {action} exists, create first")
        return action
    
    @api_router.get('/auth/export', tags=['Config'])
    async def export_auth_config():
        return {
            'users': [user.dict() for user in await Users.all()],
            'groups': [group.dict() for group in await Groups.all()],
            'roles': [role.dict() for role in await Roles.all()],
            'actions': [action.dict() for action in await Actions.all()]
        }
    
    class Config(BaseModel):
        users: Optional[List[Users]]
        groups: Optional[List[Groups]]
        roles: Optional[List[Roles]]
        actions: Optional[List[Actions]]


    @api_router.post('/auth/import', tags=['Config'])
    async def import_auth_config(config: Config):
        config = dict(config)
        if 'actions' in config:
            for action in config['actions']:
                action = dict(action)
                _action = Actions(**action)
                await _action.save()

        if 'roles' in config:
            for role in config['roles']:
                role = dict(role)
                _role = Roles(**role)
                await _role.save()
                for action in role['permissions']['actions']:
                    await verify_action(action)
        
        if 'groups' in config:
            for group in config['groups']:
                group = dict(group)
                _group = Groups(
                    **group
                )
                await _group.save()
                for role_name in group['roles']['roles']:
                    await verify_role(role_name)

        if 'users' in config:
            for user in config['users']:
                user = dict(user)
                _user = Users(**user)
                await _user.save()

        return f"import_auth_config - completed"

    @api_router.get('/auth/serviceaccount/token/{service}', response_model=Token, tags=['Token'])
    async def get_service_account_token(service: str):
        service_user = await Users.get(username=service)

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
    

    @api_router.get('/auth/oauth', response_model=List[OauthConfig])
    async def get_oauth_providers():
        return await OauthConfig.all()

    @api_router.post('/auth/oauth/{provider}')
    async def configure_oauth_provider(provider: str, oauth_config: OauthConfigInput):
        oauth_groups = [
            await verify_group(group)
            for group in oauth_config.default_groups
        ]
        oauth_config = oauth_config.dict()
        oauth_config['default_groups'] = oauth_groups
        oauth_config['enabled'] = 'enabled' in oauth_config['enabled']
        oauth_config['provider'] = provider
        oauth = OauthConfig(
            **oauth_config
        )
        await oauth.save()
        return f"{provider} OAuth Configured"

    @server.server.post('/auth/token/oauth/google', include_in_schema=False)
    async def create_google_oauth_token_api(
        request: Request, 
        response: Response,
        redirect: bool = True,
        include_token: bool = False 
    ):
        token = await server.generate_google_oauth_token(request)
        # add token to cookie
        response.set_cookie('token', token)

        redirect_ref = server.ADMIN_PREFIX

        if 'ref' in request.cookies:
            redirect_ref = request.cookies['ref']
            response.delete_cookie('ref')

        if redirect:
            return RedirectResponse(redirect_ref, headers=response.headers, status_code=HTTP_302_FOUND)
        # not redirecting 
        
        decoded_token = server.decode_token(token)[1]
        response_body = {'exp': decoded_token['exp'], 'auth': True}
        if include_token:
            response_body['token'] = token
        return HTMLResponse(
            content=json.dumps(response_body), 
            status_code=200, 
            headers=response.headers
        )

    @server.server.post('/auth/token/refresh', response_model=Token, tags=['Token'])
    async def refresh_access_token(token: str = Depends(server.oauth2_scheme)):
        try:
            token = server.decode_token(token)[1]
            user_in_token = token['permissions']['users'][0]
            user = await Users.get(username=user_in_token)

            server.log.warning(f"refresh_access_token: called for user: {user[0]}")
            # get user permissions
            permissions = await server.get_user_permissions(user_in_token)

            # generate RSA token
            token = await server.issue_token(permissions)
            return {
                "access_token": token, 
                "token_type": "bearer"
            }

        except Exception:
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
            permissions = await server.get_user_permissions(user.username)
            token = await server.issue_token(permissions)
            return {
                "access_token": token, 
                "token_type": "bearer"
            }
        raise InvalidUsernameOrPassword
    server.generate_auth_token = generate_auth_token

    @server.server.post('/auth/token', response_model=Token, tags=['Token'])
    async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
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
        new_user = await PendingUsers.get(activation_code=code)

        if not new_user:
            raise InvalidActivationCode()
        
        user_info = new_user.user_info

        # decode
        user_info = server.decode(user_info)[1]['user_info']

        user = Users(
            username=user_info['username'],
            password=user_info['password'],
            account_type='user',
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
            easyauth_provider = await OauthConfig.filter(
                provider='easyauth'
            )

            if easyauth_provider.default_groups and easyauth_provider.enabled:
                user_info['groups'] = easyauth_provider.default_groups

        try:
            register_user = RegisterUser(
                username=user_info['username'],
                full_name=user_info['full name'],
                password1=user_info['password'],
                password2=user_info['repeat password'],
                email=user_info['email address']
            )
            user = UsersInput(
                username=user_info['username'],
                password=user_info['password'],
                full_name=user_info['full name'],
                email=user_info['email address'],
                groups=user_info['groups'] if 'groups' in user_info else []
            )
        except ValueError as e:
            raise HTTPException(
                status_code=422,
                detail=f"{str(repr(e))} - error registering user"
            )
        
        # check for duplicate user
        duplicate = await Users.get(username=user_info['username'])
        if duplicate:
            raise DuplicateUserError(duplicate[0]['username'])

        email_config = await EmailConfig.all()
        
        if email_config and email_config[0]['send_activation_emails']:

            # generate activation code
            activation_code = server.generate_random_string(16)

            # encrypt user details with activation code & store
            encoded_data = server.encode(user_info=user_info)

            # insert into unactivated users
            await PendingUsers.create(
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
    async def create_user(user: UsersInput, response_type: str = None):
        response = await __create_user(user)
        if not response_type == 'html':
            return response
        return 
        
    async def __create_user(user: Users):

        if not await Users.get(username=user.username) is None:
            raise HTTPException(status_code=400, detail=f"{user['username']} already exists")

        user_groups = [
            await verify_group(group)
            for group in user.groups
        ]

        # encode password before storing
        user.password = server.encode_password(user.password)

        user = user.dict()
        user['groups'] = user_groups

        await Users.create(**user)

        # trigger some activation email later?
        return f"{user['username']} created"
    
    server.create_user = __create_user
        
    @api_router.put('/auth/service', status_code=201, actions=['CREATE_USER'], tags=['Users'])
    async def create_service(service: UsersInput):

        if not await Services.get(username=service.username) is None:
            raise HTTPException(status_code=400, detail=f"{service.username} already exists")

        user_groups = [
            await verify_group(group)
            for group in user.groups
        ]
        
        service = service.dict()
        service['account_type'] = 'service'
        service['groups'] = user_groups

        await Services.create(**service)
        # trigger some activation email later?

        return f"{service['username']} created"

    class UserGroup(BaseModel):
        groups: list

    class UserUpdate(BaseModel):
        full_name: Optional[str]
        password: Optional[str]
        email: Optional[str]
        groups: Optional[List[str]]

    @api_router.post('/auth/user/{username}', tags=['Users'])
    async def update_user(
        username: str,
        update: dict
    ):

        user_to_update = await verify_user(username)
        
        update = {k: v for k, v in dict(update).items() if not v is None}

        to_update = {}
        for k, v in update.copy().items():
            if v == '':
                continue
            if k == 'groups':
                user_groups = []
                for group in v:
                    user_groups.append(await verify_group(group))
                to_update[k] = user_groups
            else:
                to_update[k] = v
                
        update = to_update

        if "password" in update:
            # encode password before storing
            update['password'] = server.encode_password(update['password'])

        for item, value in update.items():
            setattr(user_to_update, item, value)

        await user_to_update.update()

        return f"{username} updated"

    @api_router.delete('/auth/user', tags=['Users'])
    async def delete_user(username: str):
        user = await verify_user(username)
        await user.delete()
        return f"{username} deleted"

    @api_router.get('/auth/users', tags=['Users'], response_model=List[Users])
    async def get_all_users():
        return await Users.all()

    @api_router.get('/auth/users/{username}', tags=['Users'])
    async def get_user(username: str):
        return await get_user_details(username)

    async def get_user_details(username: str):
        user = await verify_user(username)
        user = user.dict()
        permissions = await server.get_user_permissions(username)
        user['permissions'] = permissions
        return user
        
    server.get_user_details = get_user_details

    # Groups

    @api_router.put('/auth/group', status_code=201, tags=['Groups'])
    async def create_group(group: GroupsInput):
        if not await Groups.get(group_name=group.group_name) is None:
            raise HTTPException(status_code=400, detail=f"{group.group_name} already exists")

        roles_in_group = [
            await verify_role(role)
            for role in group.roles
        ]
        await Groups.create(
            group_name=group.group_name,
            roles=roles_in_group
        )

        return f"group {group.group_name} created"

    class UpdateRoles(BaseModel):
        roles: list

    @api_router.post('/auth/group/{group}', status_code=200, tags=['Groups'])
    async def update_group(group: str, roles: UpdateRoles):
        roles = dict(roles)
        group_to_update =  await verify_group(group)
        
        roles_in_group = [
            await verify_role(role)
            for role in roles['roles']
        ]

        group_to_update.roles = roles_in_group
        await group_to_update.update()

        return f"group {group} updated"
        
    @api_router.delete('/auth/group', tags=['Groups'])
    async def delete_group(group_name: str):
        group = await verify_group(group_name)
        await group.delete()
        return f"{group_name} deleted"

    @api_router.get('/auth/groups', tags=['Groups'])
    async def get_all_groups():
        return await Groups.all()

    @api_router.get('/auth/groups/{group_name}', tags=['Groups'])
    async def get_group(group_name: str):
        return await verify_group(group_name)

    # Roles

    @api_router.put('/auth/role', status_code=201, tags=['Roles'])
    async def create_role(role: RolesInput):

        if not await Roles.get(role=role.role) is None:
            raise HTTPException(status_code=400, detail=f"{role.role} already exists")
        
        actions_in_role = [
            await verify_action(action)
            for action in role.actions
        ]

        role = await Roles.create(
            role = role.role,
            actions=actions_in_role
        )
        
        return f"role {role.role} created"

    class UpdateActions(BaseModel):
        actions: list

    @api_router.post('/auth/role/{role}', status_code=200, tags=['Roles'])
    async def update_role(role: str, actions: UpdateActions):
        actions = dict(actions)
        role_to_update = await verify_role(role)

        actions_in_role = [
            await verify_action(action)
            for action in actions['actions']
        ]
            
        role_to_update.actions = actions_in_role

        await role_to_update.update()

        return f"role {role} updated"

    @api_router.delete('/auth/role', tags=['Roles'])
    async def delete_role(role: str):
        role = await verify_role(role)
        await role.delete()
        return f"{role} deleted"

    @api_router.get('/auth/roles', tags=['Roles'])
    async def get_all_roles():
        return await Roles.all()

    @api_router.get('/auth/roles/{role}', tags=['Roles'])
    async def get_role(role: str):
        await verify_role(role)
        return await Roles.get(role=role)

    ## Permissions 

    @api_router.put('/auth/actions', status_code=201, tags=['Actions'])
    async def create_permission(action: Actions):
        if not await Actions.get(action=action.action) is None:
            raise HTTPException(status_code=400, detail=f"{action.action} already exists")

        await action.insert()
        return f"permission {action.action} created"

    class UpdateDetails(BaseModel):
        details: str

    @api_router.post('/auth/actions', status_code=200, tags=['Actions'])
    async def update_permission(action: str, details: UpdateDetails):
        action = await verify_action(action)
        action.details = details.details

        await action.update()

        return f"action {action.action} updated"

    @api_router.delete('/auth/action', tags=['Actions'])
    async def delete_permission(action):
        action = await verify_action(action)
        await action.delete()
        return f"{action.action} deleted"

    @api_router.get('/auth/actions', tags=['Actions'])
    async def get_all_permissons():
        return await Actions.all()

    @api_router.get('/auth/actions/{action}', tags=['Actions'])
    async def get_permission(action: str):
        return await verify_action(action)
    
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