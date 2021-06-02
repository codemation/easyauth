import os, sys
import pytest
from fastapi.testclient import TestClient
from fastapi import FastAPI
from easyauth.server import EasyAuthServer
# import sub modules
from .finance import finance
from .hr import hr
from .marketing import marketing

server = FastAPI()

os.environ['EASYAUTH_PATH'] = os.environ['PWD']

@server.on_event('startup')
async def startup():
    server.auth = await EasyAuthServer.create(
        server, 
        '/auth/token',
        auth_secret='abcd1234',
        admin_title='EasyAuth - Company',
        admin_prefix='/admin',
        env_from_file='server_sqlite.json'
    )

    finance_auth_router = server.auth.create_api_router(prefix='/finance', tags=['finance'])
    hr_auth_router = server.auth.create_api_router(prefix='/hr', tags=['hr'])
    marketing_auth_router = server.auth.create_api_router(prefix='/marketing', tags=['marketing'])

    # send auth routers to setup of each sub-module
    await finance.setup(finance_auth_router)
    await hr.setup(hr_auth_router)
    await marketing.setup(marketing_auth_router)
    #nothings

    test_auth_router = server.auth.create_api_router(prefix='/testing', tags=['testing'])

    # grants access to users matching default_permissions
    @test_auth_router.get('/default')
    async def default():
        return f"I am default"

    # grants access to only specified users
    @test_auth_router.get('/', users=['john'])
    async def root():
        return f"I am root"

    # grants access to members of 'users' or 'admins' group.
    @test_auth_router.get('/groups', groups=['basic_users', 'admins'])
    async def groups():
        return f"I am groups"

    # grants access to all members of 'users' group 
    # or a groups with role of 'basic' or advanced
    @test_auth_router.get('/roles', roles=['basic', 'advanced'], groups=['users'])
    async def roles():
        return f"Roles and Groups"

    # grants access to all members of groups with a roles granting 'BASIC_CREATE'
    @test_auth_router.get('/actions', actions=['BASIC_CREATE'])
    async def action():
        return f"I am actions"


def test_authentication():
    with TestClient(server) as test_client:
        prefix = server.auth.ADMIN_PREFIX

        # verify endpoint access fails without token

        response = test_client.get("/finance/")
        assert response.status_code == 401, f"{response.text} - {response.status_code}"

        # verify token generation with bad credentials

        bad_credentials = {
            'username': 'admin',
            'password': 'BAD'
        }

        response = test_client.post("/auth/token/login", json=bad_credentials)
        assert response.status_code == 401, f"{response.text} - {response.status_code}"


        # verify token generation with correct credentials

        good_credentials = {
            'username': 'admin',
            'password': 'abcd1234'
        }
        
        response = test_client.post("/auth/token/login", json=good_credentials)
        assert response.status_code == 200, f"{response.text} - {response.status_code}"

        token = response.json()
        for expected in {"access_token", "token_type"}:
            assert "access_token" in token, f"missing {expected} in token {token}"

        # verify endpoint access while using token

        headers = {'Authorization': f"Bearer {token['access_token']}"}

        response = test_client.get("/finance/", headers=headers)
        assert response.status_code == 200, f"{response.text} - {response.status_code}"

        # test user creation 
        new_user = {
            "username": "john",
            "password": "abcd1234",
            "full_name": "john doe",
            "email": "john.doe@easyauth.com",
            "groups": [
                "administrators"
            ]
        }
        
        # check if user exists, delete if existing
        response = test_client.get("/auth/users/john", headers=headers)
        assert response.status_code in {200, 404}, f"{response.text} - {response.status_code}"
        if response.status_code == 200:
            # delete user
            response = test_client.delete("/auth/user?username=john", headers=headers)
            assert response.status_code == 200, f"{response.text} - {response.status_code}"

        # create user 

        response = test_client.put("/auth/user", headers=headers, json=new_user)
        assert response.status_code == 201, f"{response.text} - {response.status_code}"

        # test updating user
        response = test_client.post(
            "/auth/user/john", 
            headers=headers, 
            json={
                "full_name": "john j doe",
                "password": "new1234"
            }
        )

        assert response.status_code == 200, f"{response.text} - {response.status_code}"

        # test deleting user 
        response = test_client.delete("/auth/user?username=john", headers=headers)
        assert response.status_code == 200, f"{response.text} - {response.status_code}"

        # re-create & test token login with new user

        response = test_client.put("/auth/user", headers=headers, json=new_user)
        assert response.status_code == 201, f"{response.text} - {response.status_code}"
    

        response = test_client.post("/auth/token/login", json={
            "username": new_user['username'],
            "password": new_user['password']
        })
        assert response.status_code == 200, f"{response.text} - {response.status_code}"

        token = response.json()
        headers = {'Authorization': f"Bearer {token['access_token']}"}

        response = test_client.get("/finance/", headers=headers)
        assert response.status_code == 200, f"{response.text} - {response.status_code}"

        # test permission creation

        # check if action exists, delete if existing
        response = test_client.get("/auth/permission/BASIC_CREATE", headers=headers)
        assert response.status_code in {200, 404}, f"{response.text} - {response.status_code}"
        if response.status_code == 200:
            # delete user
            response = test_client.delete("/auth/permission?action=BASIC_CREATE", headers=headers)
            assert response.status_code == 200, f"{response.text} - {response.status_code}"

        new_action = {
            "action": "BASIC_CREATE",
            "detail": "BASIC CREATE permissions"
        }
        response = test_client.put("/auth/permissions", headers=headers, json=new_action)
        assert response.status_code == 201, f"{response.text} - {response.status_code}"
    

        # test updating permission
        response = test_client.post(
            "/auth/permissions?action=BASIC_CREATE", 
            headers=headers, 
            json={
                "detail": "BASIC CREATE updated"
            }
        )

        assert response.status_code == 200, f"{response.text} - {response.status_code}"

    
        # test role creation 

        # check if role exists, delete if existing
        response = test_client.get("/auth/roles/basic", headers=headers)
        assert response.status_code in {200, 404}, f"{response.text} - {response.status_code}"
        if response.status_code == 200:
            # delete role
            response = test_client.delete("/auth/role?role=basic", headers=headers)
            assert response.status_code == 200, f"delete role {response.text} - {response.status_code}"
        
        # create role 

        new_role = {
            "role": "basic",
            "permissions": [
                "BASIC_CREATE"
            ]
        }

        response = test_client.put("/auth/role", headers=headers, json=new_role)
        assert response.status_code == 201, f"create role {response.text} - {response.status_code}"

        # test updating role
        response = test_client.post(
            "/auth/role/basic", 
            headers=headers, 
            json={
                "actions": [
                    "BASIC_CREATE"
                ]
            }
        )

        assert response.status_code == 200, f"update role {response.text} - {response.status_code}"

        # create group

        # check if group exists, delete if existing
        response = test_client.get("/auth/groups/basic_users", headers=headers)
        assert response.status_code in {200, 404}, f"get group{response.text} - {response.status_code}"
        if response.status_code == 200:
            # delete group
            response = test_client.delete("/auth/group?group_name=basic_users", headers=headers)
            assert response.status_code == 200, f"delete group {response.text} - {response.status_code}"
        

        # create group 

        new_group = {
            "group_name": "basic_users",
            "roles": [
                "basic"
            ]
        }

        response = test_client.put("/auth/group", headers=headers, json=new_group)
        assert response.status_code == 201, f"create group {response.text} - {response.status_code}"

        # test updating role
        response = test_client.post(
            "/auth/group/basic_users", 
            headers=headers, 
            json={
                "roles": [
                    "basic",
                    "admin"
                ]
            }
        )

        assert response.status_code == 200, f"update group {response.text} - {response.status_code}"

        # verify permissoin denied without required action
        response = test_client.get("/testing/actions", headers=headers)
        assert response.status_code == 403, f"{response.text} - {response.status_code}"

        # verify permissoin denied without required role
        response = test_client.get("/testing/roles", headers=headers)
        assert response.status_code == 403, f"{response.text} - {response.status_code}"

        # verify permissoin denied without required group
        response = test_client.get("/testing/groups", headers=headers)
        assert response.status_code == 403, f"{response.text} - {response.status_code}"
    
        # verify permissoin allowed for specific user
        response = test_client.get("/testing/", headers=headers)
        assert response.status_code == 200, f"{response.text} - {response.status_code}"

        # add user to group with 

        response = test_client.post(
            "/auth/user/john", 
            headers=headers, 
            json={
                "groups": [
                    "basic_users"
                ]
            }
        )

        # verify failures pre token generation

        response = test_client.get("/testing/actions", headers=headers)
        assert response.status_code == 403, f"{response.text} - {response.status_code}"

        # verify permissoin denied without required action
        response = test_client.get("/testing/roles", headers=headers)
        assert response.status_code == 403, f"{response.text} - {response.status_code}"

        # verify permissoin denied without required action
        response = test_client.get("/testing/groups", headers=headers)
        assert response.status_code == 403, f"{response.text} - {response.status_code}"
    
        # re create token with updated permissions

        response = test_client.post("/auth/token/login", json={
            "username": new_user['username'],
            "password": new_user['password']
        })
        assert response.status_code == 200, f"{response.text} - {response.status_code}"

        token = response.json()
        headers = {'Authorization': f"Bearer {token['access_token']}"}

        # verify success with updated token

        response = test_client.get("/testing/actions", headers=headers)
        assert response.status_code == 200, f"new_token - actions {response.text} - {response.status_code}"

        # verify permissoin denied without required action
        response = test_client.get("/testing/roles", headers=headers)
        assert response.status_code == 200, f"new_token - roles {response.text} - {response.status_code}"

        # verify permissoin denied without required action
        response = test_client.get("/testing/groups", headers=headers)
        assert response.status_code == 200, f"new_token - groups {response.text} - {response.status_code}"

        decoded_token = server.auth.decode_token(token['access_token'])
        print(decoded_token)
        assert 'token_id' in decoded_token[1], f"{decoded_token}"

        # revoke token & test access failure
        response = test_client.delete(f"/auth/token?token_id={decoded_token[1]['token_id']}", headers=headers)
        assert response.status_code == 200, f"revoke token {response.text} - {response.status_code}"

        response = test_client.get("/testing/actions", headers=headers)
        assert response.status_code == 403, f"revoke_token - actions - {response.status_code} - {response.text}"

        response = test_client.get("/testing/roles", headers=headers)
        assert response.status_code == 403, f"revoke_token - roles {response.status_code} - {response.text}"

        response = test_client.get("/testing/groups", headers=headers)
        assert response.status_code == 403, f"revoke_token - groups - {response.status_code} - {response.text}"


#def test_basic_endpoint(test_client):
#    response = test_client.get("/finance/data")
#    assert response.status_code == 200, response.text