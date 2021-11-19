from typing import Mapping
from pydantic import BaseModel, root_validator, EmailStr
from enum import Enum
from pydbantic import DataBaseModel
from typing import Optional, Union, List

# Model used to verify input when registering
# a new user
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

class AccountType(str, Enum):
    user: str = 'user'
    service: str = 'service'

# RBAC Models 

class Actions(DataBaseModel):
    action: str
    details: str

class Roles(DataBaseModel):
    role: str
    actions: List[Actions]

class RolesInput(Roles):
    actions: List[str]


class Groups(DataBaseModel):
    group_name: str
    roles: List[Roles]
    
class GroupsInput(Groups):
    roles: List[str]

class BaseUser(DataBaseModel):
    username: str = None
    account_type: AccountType
    groups: List[Groups]

class Users(BaseUser):
    password: Optional[str] = None
    account_type: AccountType = AccountType.user
    email: str = None
    full_name: Optional[str] = None

class UsersInput(Users):
    groups: List[str]

class Services(BaseUser):
    account_type: AccountType = AccountType.service

class Tokens(DataBaseModel):
    token_id: str
    username: str
    issued: str
    expiration: str
    token: dict

class PendingUsers(DataBaseModel):
    activation_code: str
    user_info: str

# Email

class EmailConfig(DataBaseModel):
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
    
class OauthConfig(DataBaseModel):
    provider: str
    client_id: str
    enabled: bool
    default_groups: List[Groups] = []
class OauthConfigInput(OauthConfig):
    provider: str = 'UNSET'
    default_groups: List[str] = []
    enabled: List[str] = []

async def tables_setup(server):
    """
    Create default adminstrator user, admin group and roles if 
    no users exist
    """
    log = server.log
    db = server.db

    new_user = not len(await Users.all()) > 0

    if new_user and server.leader:
        random_password = server.generate_random_string(8)
        create_user = Actions(
            action='CREATE_USER',
            details='default action for creating users'
        )
        await create_user.save()

        admin_role = Roles(
            role='admin',
            actions=[create_user]
        )
        await admin_role.save()

        administrators = Groups(
            group_name='administrators',
            roles=[admin_role]
        )
        await administrators.save()

        await Users.create(
            username='admin',
            password=server.encode_password(random_password),
            account_type='user',
            groups=[administrators]
        )

        server.log.error(f"detected new EasyAuth server, created admin user with password: {random_password}")

    # set the default oauth configuration, if 
    # unconfigured thus far

    easyauth = await OauthConfig.filter(provider='easyauth')

    if not easyauth and server.leader:
        await OauthConfig.create(
            provider='easyauth',
            client_id='EASYAUTH',
            enabled=True
        )

        await OauthConfig.create(
            provider='google',
            client_id='',
            enabled=False
        )