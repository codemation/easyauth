from pydantic import BaseModel
from typing import Optional, Union

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


async def tables_setup(server):
    log = server.log
    db = server.db

    old_user_schema = False
    old_groups_schema = False

    new_user = not 'users' in db.tables

    if 'users' in db.tables:
        if 'groups' in db.tables['users'].columns:
            log.warning(f"old user schema detected, creating backup & migrating")
            old_schema_user_copy = await db.tables['users'].select('*')
            old_user_schema = True
            import json, time
            with open(f'users_backup_{time.time()}', 'w') as backup:
                backup.write(json.dumps({'users_backup': old_schema_user_copy}))
            await db.remove_table('users')
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
            ('username', str, 'UNIQUE NOT NULL'),
            ('full_name', str), 
            ('email', str),
            ('account_type', str), # user / service 
            ('password', str),
            ('user_groups', str),
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
            ('group_name', str, 'UNIQUE NOT NULL'), 
            ('roles', str), 
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
            ('role', str, 'UNIQUE NOT NULL'), 
            ('permissions', str)
        ],
        'role',
        cache_enabled=True
    )

    await db.create_table(
        'permissions', 
            [
                ('action', str, 'NOT NULL'),
                ('details', str)
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
            if 'groups' in kwargs:
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

    server.auth_users = Users()
    server.auth_groups = Groups()
    server.auth_roles = Roles()
    server.auth_actions = Actions()


    if new_user:
        import random, string
        def get_random_string(length):
            letters = string.ascii_lowercase
            result_str = ''.join(random.choice(letters) for i in range(length))
            return result_str
        random_password = get_random_string(8)
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