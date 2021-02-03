from pydantic import BaseModel
from typing import Optional

class User(BaseModel):
    username: str = None
    password: Optional[str] = None
    full_name: Optional[str] = None
    account_type: str = 'user|service'
    email: str = None
    groups: dict = {'groups': ['administrators']}

class Group(BaseModel):
    group_name: str
    roles: dict = {'roles': ['auth']}

class Role(BaseModel):
    role: str
    permissions: dict = {'actions': ['CREATE_USER']}

class Permission(BaseModel):
    action: str = "CREATE_USER|CREATE_GROUP"
    details: str = "Discription on what this allows"


async def tables_setup(server):
    db = server.db
    new_user = not 'users' in db.tables
    await db.create_table(
        'users', 
        [
            ('username', str, 'UNIQUE NOT NULL'),
            ('full_name', str), 
            ('email', str),
            ('account_type', str), # user / service 
            ('password', str),
            ('groups', str),
        ],
        'username',
        cache_enabled=True
    )

    # Groups 

    await db.create_table(
        'groups', 
            [
            ('group_name', str, 'UNIQUE NOT NULL'), 
            ('roles', str), 
            ],
            'group_name',
            cache_enabled=True
        )

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


    if new_user:
        import random, string
        def get_random_string(length):
            letters = string.ascii_lowercase
            result_str = ''.join(random.choice(letters) for i in range(length))
            return result_str
        random_password = get_random_string(8)
        await db.tables['users'].insert(
            username='admin',
            password=server.encode_password(random_password),
            groups={'groups': ['administrators']}
        )
        server.log.error(f"detected new EasyAuth server, created admin user with password: {random_password}")

        await db.tables['groups'].insert(
            group_name='administrators',
            roles={'roles': ['admin']}
        )
        await db.tables['roles'].insert(
            role='admin',
            permissions={'actions': ['CREATE_USER']}
        )
        await db.tables['permissions'].insert(
            action='CREATE_USER',
            details='DEFAULT privelidge for creating users'
        )
