from pydantic import BaseModel, ValidationError, root_validator, EmailStr
from typing import Optional, Union

class RegisterUser(BaseModel):
    username: str
    password1: str
    password2: str
    full_name: str = None
    email: EmailStr = None
    
    @root_validator
    def check_passwords_match(cls, values):
        pw1, pw2 = values.get('password1'), values.get('password2')
        if pw1 is not None and pw2 is not None and pw1 != pw2:
            raise ValueError('passwords do not match')
        return values
        
class ActivationCode(BaseModel):
    activation_code: str


class User(BaseModel):
    username: str = None
    password: Optional[str] = None
    full_name: Optional[str] = None
    email: str = None
    groups: Union[list, dict] = None

class Service(BaseModel):
    username: str = None
    groups: Union[list, dict] = ['<group_name>']

class Group(BaseModel):
    group_name: str
    roles: Union[list, dict] = ['<role_name>']

class Role(BaseModel):
    role: str
    permissions: Union[list,dict] = ['CREATE_USER']

class Permission(BaseModel):
    action: str = "CREATE_USER|CREATE_GROUP"
    details: str = "Discription on what this allows"

class EmailConfig(BaseModel):
    MAIL_USERNAME: str
    MAIL_PASSWORD: str
    MAIL_FROM: str
    MAIL_SERVER: str
    MAIL_PORT: int
    MAIL_FROM_NAME: str
    MAIL_TLS: bool = True
    MAIL_SSL: bool = False
    SEND_ACTIVATION_EMAILS: bool

class EmailSetup(BaseModel):
    MAIL_USERNAME: str
    MAIL_PASSWORD: str
    MAIL_FROM: str
    MAIL_SERVER: str
    MAIL_PORT: int
    MAIL_FROM_NAME: str
    MAIL_TLS: list = []
    MAIL_SSL: list = []
    SEND_ACTIVATION_EMAILS: list = []

class Email(BaseModel):
    subject: str
    recipients: Union[list, str]
    email_body: str
    
class OauthConfig(BaseModel):
    client_id: str
    enabled: bool
    default_groups: list

async def tables_setup(server):
    log = server.log
    db = server.db

    old_user_schema = False
    old_groups_schema = False

    new_user = not 'users' in db.tables

    if 'users' in db.tables:
        """
        if 'groups' in db.tables['users'].columns:
            log.warning(f"old user schema detected, creating backup & migrating")
            old_schema_user_copy = await db.tables['users'].select('*')
            old_user_schema = True
            import json, time
            with open(f'users_backup_{time.time()}', 'w') as backup:
                backup.write(json.dumps({'users_backup': old_schema_user_copy}))
            await db.remove_table('users')
        """
    if 'groups' in db.tables:
        log.warning(f"old group schema detected, creating backup & migrating")
        old_schema_groups_copy = await db.tables['groups'].select('*')
        old_groups_schema = True
        import json, time
        with open(f'groups_backup_{time.time()}', 'w') as backup:
            backup.write(json.dumps({'groups_backup': old_schema_groups_copy}))
        await db.remove_table('groups')

    await db.create_table(
        'users', 
        [
            ['username', 'str', 'UNIQUE NOT NULL'],
            ['full_name', 'str'], 
            ['email', 'str'],
            ['account_type', 'str'], # user / service 
            ['password', 'str'],
            ['user_groups', 'str'],
        ],
        'username',
        cache_enabled=True
    )
    if old_user_schema:
        for user in old_schema_user_copy:
            if 'groups' in user:
                user['user_groups'] = user.pop('groups')
            await db.tables['users'].insert(**user)


    # Groups 

    await db.create_table(
        'user_groups', 
            [
                ['group_name', 'str', 'UNIQUE NOT NULL'], 
                ['roles', 'str'], 
            ],
            'group_name',
            cache_enabled=True
        )
    if old_groups_schema:
        for group in old_schema_groups_copy:
            await db.tables['user_groups'].insert(**group)


    await db.create_table(
        'roles', 
        [
            ['role', 'str', 'UNIQUE NOT NULL'], 
            ['permissions', 'str']
        ],
        'role',
        cache_enabled=True
    )

    await db.create_table(
        'permissions', 
            [
                ['action', 'str', 'NOT NULL'],
                ['details', 'str']
            ],
            'action',
            cache_enabled=True
    )


    class Users:
        async def select(self, *args, **kwargs):
            """
            converts user_groups -> "groups"
            """
            args = set(args)
            if 'groups' in args:
                args.remove('groups')
                args = list(args) + ['user_groups']
            if 'groups' in kwargs:
                kwargs['user_groups'] = kwargs.pop('groups')

            selection = await server.db.tables['users'].select(*args, **kwargs)
            for user in selection:
                if 'user_groups' in user:
                    user['groups'] = user.pop('user_groups')
            return selection
        async def update(self, **kwargs):
            where = kwargs.pop('where')
            
            if 'groups' in kwargs:
                kwargs['user_groups'] = kwargs.pop('groups')
            return await server.db.tables['users'].update(
                where=where,
                **kwargs
            )
        async def delete(self, where: dict):
            if 'groups' in where:
                where['users_groups'] = where.pop('groups')
            return await server.db.tables['users'].delete(where=where)
        async def insert(self, **kwargs):
            if 'groups' in kwargs:
                kwargs['user_groups'] = kwargs.pop('groups')
            return await server.db.tables['users'].insert(**kwargs)
        def __getitem__(self, item):
            async def get_item():
                user = await server.db.tables['users'][item]
                if user is None:
                    return user

                if 'user_groups' in user:
                    user['groups'] = user.pop('user_groups')
                return user
            return get_item()
                
            
    class Groups:
        select = db.tables['user_groups'].select
        update = db.tables['user_groups'].update
        delete = db.tables['user_groups'].delete
        insert = db.tables['user_groups'].insert
        def __getitem__(self, item):
            return server.db.tables['user_groups'][item]
    
    class Roles:
        select = server.db.tables['roles'].select
        update = server.db.tables['roles'].update
        delete = server.db.tables['roles'].delete
        insert = server.db.tables['roles'].insert
        def __getitem__(self, item):
            return server.db.tables['roles'][item]
    class Actions:
        select = server.db.tables['permissions'].select
        update = server.db.tables['permissions'].update
        delete = server.db.tables['permissions'].delete
        insert = server.db.tables['permissions'].insert
        def __getitem__(self, item):
            return server.db.tables['permissions'][item]
    
    await db.create_table(
        'tokens', 
            [
                ['token_id', 'str'],
                ['username', 'str'],
                ['issued', 'str'],
                ['expiration', 'str'],
                ['token', 'str']
            ],
            'token_id',
            cache_enabled=True
    )
    class Tokens:
        select = server.db.tables['tokens'].select
        update = server.db.tables['tokens'].update
        delete = server.db.tables['tokens'].delete
        insert = server.db.tables['tokens'].insert
        def __getitem__(self, item):
            return server.db.tables['tokens'][item]

    server.auth_users = Users()
    server.auth_groups = Groups()
    server.auth_roles = Roles()
    server.auth_actions = Actions()
    server.auth_tokens = Tokens()


    if new_user:
        random_password = server.generate_random_string(8)
        await server.auth_users.insert(
            username='admin',
            password=server.encode_password(random_password),
            account_type='user',
            groups={'groups': ['administrators']}
        )
        server.log.error(f"detected new EasyAuth server, created admin user with password: {random_password}")

        await server.auth_groups.insert(
            group_name='administrators',
            roles={'roles': ['admin']}
        )
        await server.auth_roles.insert(
            role='admin',
            permissions={'actions': ['CREATE_USER']}
        )
        await server.auth_actions.insert(
            action='CREATE_USER',
            details='DEFAULT privelidge for creating users'
        )

    # setup env table - key-value store 
    await db.create_table(
        'env', 
        [
            ['key', 'str', 'UNIQUE NOT NULL'],
            ['value', 'str']
        ],
        'key',
        cache_enabled=True
    )

    # setup mail configuration

    await db.create_table(
        'email_config', 
        [
            ['username', 'str', 'UNIQUE NOT NULL'],
            ['password', 'str'],
            ['mail_from', 'str'],
            ['mail_from_name', 'str'],
            ['server', 'str'],
            ['port', 'str'],
            ['mail_tls', 'bool'],
            ['mail_ssl', 'bool'],
            ['is_enabled', 'bool'],
            ['send_activation_emails', 'bool']
        ],
        'username',
        cache_enabled=True
    )

    await db.create_table(
        'pending_users', 
        [
            ['activation_code', 'str', 'UNIQUE NOT NULL'],
            ['user_info', 'str'],
        ],
        'activation_code', 
        cache_enabled=True
    )

    await db.create_table(
        'oauth', 
        [
            ['provider', 'str', 'UNIQUE NOT NULL'],
            ['client_id', 'str'],
            ['default_groups', 'str'],
            ['enabled', 'bool']
        ],
        'provider',
        cache_enabled=True
    )
    easyauth = await db.tables['oauth'].select(
        '*',
        where={'provider': 'easyauth'}
    )
    if not easyauth:
        await db.tables['oauth'].insert(
            provider='easyauth',
            client_id='EASYAUTH',
            default_groups={'default_groups': []},
            enabled=True
        )
        await db.tables['oauth'].insert(
            provider='google',
            client_id='',
            default_groups={'default_groups': []},
            enabled=False
        )

