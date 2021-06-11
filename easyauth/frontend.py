from copy import deepcopy
from re import sub
from easyadmin import Admin, buttons, forms, html_input, row, card, modal, admin
from easyadmin.elements import scripts
from easyadmin.pages import register
from fastapi.responses import HTMLResponse
from fastapi import HTTPException, Request

async def frontend_setup(server):

    log = server.log

    admin_gui = server.api_routers[1]
    admin_prefix = server.ADMIN_PREFIX

    server.admin = Admin(
        title=server.server.title,
        title_link = admin_prefix,
        side_bar_sections = [
            {
                'items': [
                    {
                        'name':  'Users',
                        'href': f'{admin_prefix}/users',
                        'icon': 'user',
                        #'onclick': f"OnClickUpdate('{admin_prefix}/users', 'page-top')",
                        'items': []
                    },
                    {
                        'name':  'Services',
                        'href': f'{admin_prefix}/services',
                        'icon': 'robot',
                        #'onclick': f"OnClickUpdate('{admin_prefix}/services', 'page-top')",
                        'items': []
                    },
                    {
                        'name':  'Groups',
                        'href': f'{admin_prefix}/groups',
                        'icon': 'users',
                        #'onclick': f"OnClickUpdate('{admin_prefix}/groups', 'page-top')",
                        'items': []
                    },
                    {
                        'name':  'Roles',
                        'href': f'{admin_prefix}/roles',
                        'icon': 'bezier-curve',
                        #'onclick': f"OnClickUpdate('{admin_prefix}/roles', 'page-top')",
                        'items': []
                    },
                    {
                        'name':  'Actions',
                        'href': f'{admin_prefix}/actions',
                        'icon': 'id-badge',
                        #'onclick': f"OnClickUpdate('{admin_prefix}/actions', 'page-top')",
                        'items': []
                    }
                ]
            },
            {
                'items': [
                    {
                        'name':  'Tokens Issued',
                        'href': f'{admin_prefix}/tokens',
                        'icon': 'key',
                        #'onclick': f"OnClickUpdate('{admin_prefix}/tokens', 'page-top')",
                        'items': []
                    }
                ]
            },
            {
                'items': [
                    {
                        'name':  'Email',
                        'href': f'{admin_prefix}/email',
                        'icon': 'envelope',
                        #'onclick': f"OnClickUpdate('{admin_prefix}/email', 'page-top')",
                        'items': [
                        ]
                    }
                ]
            },
            {
                'items': [
                    {
                        'name':  'Identity Providers',
                        'href': f'{admin_prefix}/oauth',
                        'icon': 'passport',
                        #'onclick': f"OnClickUpdate('{admin_prefix}/oauth', 'page-top')",
                        'items': [
                        ]
                    }
                ]
            },
            {
                'items': [
                    {
                        'name':  'APIs',
                        'href': f'/docs',
                        'icon': 'flag',
                        #'onclick': f"OnClickUpdate('/docs', 'page-top')",
                        'items': [
                        ]
                    }
                ]
            },
        ]
    )

    logout_modal = modal.get_modal(
        f'logoutModal',
        alert='Ready to Leave',
        body=buttons.get_button(
            'Go Back',
            color='success',
            href=f'{admin_prefix}/'
        ) +
        scripts.get_google_signout_script() + 
        buttons.get_button(
            'Log out',
            color='danger',
            onclick='signOut()'
        ),
        footer='',
        size='sm'
    )

    @admin_gui.get('/', response_class=HTMLResponse, send_token=True, include_in_schema=False)
    async def admin_home(access_token=None):
        return await _admin_users(access_token)
    @admin_gui.post('/', response_class=HTMLResponse, send_token=True, include_in_schema=False)
    async def re_admin_users(access_token=None):
        return await _admin_users(access_token)

    @admin_gui.get('/users', response_class=HTMLResponse, send_token=True, include_in_schema=False)
    async def admin_users(access_token=None):
        return await _admin_users(access_token)
    
    @admin_gui.get('/services', response_class=HTMLResponse, send_token=True, include_in_schema=False)
    async def admin_users(access_token=None):
        return await _admin_users(access_token, account_type='service')

    @admin_gui.get('/user/{username}', response_class=HTMLResponse, send_token=True, include_in_schema=False)
    async def admin_user_page(username: str, access_token: str = None):
        users = await server.auth_users.select(
            'username', where={'username': username}
        )
        if not users:
            raise HTTPException(
                status_code=404,
                detail=f"No User with name {username} exists"
            )
            
        groups = await server.auth_groups.select('group_name')
        groups = deepcopy([group['group_name'] for group in groups])

        user_page = admin.get_admin_page(
            name=username, 
            sidebar=server.admin.sidebar,
            body=await get_user_details(username, groups),
            current_user=access_token['permissions']['users'][0],
            modals=logout_modal + scripts.get_onclick_form_submit_script(transform=True),
            google=await server.get_google_oauth_client_id()
        )
        return user_page

    @admin_gui.get('/service/{username}', response_class=HTMLResponse, send_token=True, include_in_schema=False)
    async def admin_service_page(username: str, access_token: str = None):
        users = await server.auth_users.select(
            'username', where={'username': username}
        )
        if not users:
            raise HTTPException(
                status_code=404,
                detail=f"No Service with name {username} exists"
            )
            
        groups = await server.auth_groups.select('group_name')
        groups = deepcopy([group['group_name'] for group in groups])

        user_page = admin.get_admin_page(
            name=username, 
            sidebar=server.admin.sidebar,
            body=await get_user_details(username, groups),
            current_user=access_token['permissions']['users'][0],
            modals=logout_modal,
            google=await server.get_google_oauth_client_id()
        )
        return user_page


    async def get_user_details(username: str, all_groups: list):

        details = await server.get_user_details(username)
        username_normalized = sub('[@.]', '', username)
        update_form = forms.get_form(
            f'Update {username_normalized}',
            [
                html_input.get_text_input("username", value=username),
                html_input.get_text_input("password", input_type='password') 
                if details['account_type'] == 'user' else '',
                html_input.get_text_input("email", value=details['email']) + 
                html_input.get_text_input("full_name", value=details['full_name'])
                if details['account_type'] == 'user' else '',
                html_input.get_checkbox('groups', [
                    (group, True) for group in details['groups']['groups'] ] +
                    [(group, False) for group in all_groups if not group in details['groups']['groups']],
                    size=12,
                    unique_id=username
                )
            ],
            submit_name='update user',
            method='post',
            action=f'/auth/user/{username}',
            transform_id=f'Update{username_normalized}',
        )
        groups, roles, actions = [], [], [] 
        if 'groups' in details['permissions']:
            groups = [group for group in details['permissions']['groups']]
        if 'roles' in details['permissions']:
            roles = [role for role in details['permissions']['roles']]
        if 'actions' in details['permissions']:
            actions = [action for action in details['permissions']['actions']]

        modal_row = row.get_row(
            card.get_card(
                f'{username}',
                update_form,
                size=12
            )+
            card.get_card(
                f"Groups",
                ''.join([
                    buttons.get_button(
                        group,
                        color='success', 
                        href=f'#{group}',
                        onclick=f"OnClickUpdate('{admin_prefix}/group/{group}', 'page-top')"
                    ) for group in groups
                ]),
                size=4
            )+
            card.get_card(
                f"Roles",
                ''.join([
                    buttons.get_button(
                        role,
                        color='success', 
                        href=f'#{role}',
                        onclick=f"OnClickUpdate('{admin_prefix}/role/{role}', 'page-top')"
                    ) for role in roles
                ]),
                size=4
            )+
            card.get_card(
                f"Actions",
                ''.join([
                    buttons.get_button(
                        action,
                        color='success', 
                        href=f'#{action}',
                        onclick=f"OnClickUpdate('{admin_prefix}/action/{action}', 'page-top')"
                    ) for action in actions
                ]),
                size=4
            )
        )
        return modal_row

    
    async def _admin_users(access_token: str, account_type='user'):
        users = await server.auth_users.select(
            'username', 'full_name', 'email', 'account_type', 'groups',
            where={'account_type': account_type}
        )
        users = users.copy()
        
        groups = await server.auth_groups.select('group_name')
        groups = deepcopy([group['group_name'] for group in groups])
        modals = [logout_modal]

        users_table = deepcopy(users)

        for ind, user in enumerate(users):
            username = user['username']
            username_normalized = sub('[@.]', '', username)
            modals.append(
                modal.get_modal(
                    f'delete{username_normalized}Modal',
                    alert='',
                    body=forms.get_form(
                        f'Delete {account_type} {username_normalized}',
                        [
                            buttons.get_button(
                                'Go Back',
                                color='success', 
                                href=f'{admin_prefix}/'
                            )
                        ],
                        submit_name=f'delete {account_type}',
                        method='delete',
                        action=f'/auth/user?username={username}'
                    ),
                    footer='',
                    size='sm'
                )
            )
            modals.append(
                modal.get_modal(
                    f'view_{username_normalized}',
                    alert='',
                    body=await get_user_details(username, groups),
                    footer='',
                    size='lg'
            ))
            if account_type == 'service':
                modals.append(
                    modal.get_modal(
                        f'generate{username_normalized}TokenModal',
                        alert='',
                        body=forms.get_form(
                            f'Generate {username_normalized} token',
                            [
                                buttons.get_button(
                                    'Go Back',
                                    color='success', 
                                    href=f'{admin_prefix}/'
                            )],
                            submit_name=f'Create Token',
                            method='get',
                            action=f'/auth/serviceaccount/token/{username}',
                            transform_id=f'Generate{username_normalized}token'
                        ),
                        footer='',
                        size='sm'
                    )
                )
            users_table[ind]['groups'] = ''.join([
                buttons.get_button(group, color='success', href=f'{admin_prefix}/group/{group}')
                for group in users_table[ind]['groups']['groups']
            ])
            actions = ( 
                buttons.get_split_button(
                    f'view/edit',
                    icon='eye',
                    modal=f'view_{username_normalized}'
                ) + 
                buttons.get_split_button(
                    f'delete', 
                    modal=f'delete{username_normalized}Modal', 
                    color='danger',
                    icon='trash'
                )
            )
            if account_type == 'service':
                token_button = buttons.get_split_button(
                        f'generate token', 
                        modal=f'generate{username_normalized}TokenModal', 
                        color='warning',
                        icon='key'
                    )
                actions = actions + token_button
            users_table[ind][' '] = actions

        email_and_full_name_input = html_input.get_text_input("email") + html_input.get_text_input("full_name")
        
        users_default = [{
            f'{account_type}': f"No {account_type}'s created yet",
        }]

        return server.admin.table_page(
            f'{account_type}s',
            users_table if len(users_table) > 0 else users_default,
            current_user=access_token['permissions']['users'][0],
            modals=''.join(modals),
            above=scripts.get_onclick_script() + 
            scripts.get_onclick_form_submit_script(transform=True),
            below=forms.get_form(
                f'Create {account_type}',
                [
                    html_input.get_text_input("username"),
                    html_input.get_text_input("password", input_type='password')
                    if account_type =='user' else '',
                    email_and_full_name_input if account_type =='user' else '' ,
                    html_input.get_checkbox(
                        'groups', 
                        [(group, False) for group in deepcopy(groups)],
                        size=12
                    )
                ],
                submit_name=f'create {account_type}',
                method='put',
                action=f'/auth/{account_type}'
            ),
            google=await server.get_google_oauth_client_id()
        )

    async def get_group_details(group_name: str):
        group = await server.auth_groups.select(
            '*', where={'group_name': group_name}
        )
        if not group:
            raise HTTPException(
                status_code=404,
                detail=f"No Group with name {group_name} exists"
            )
        group = group[0]

        all_roles = await server.auth_roles.select('role')
        all_roles = [role['role'] for role in all_roles]

        roles = group['roles']['roles'] if isinstance(group['roles'], dict) else group['roles'] 
        roles = [role for role in roles if role in all_roles]

        permissions = []
        all_actions = await server.auth_actions.select('action')
        all_actions = [action['action'] for action in all_actions]
        for role in roles:
            actions = await server.auth_roles.select(
                'permissions', where={'role': role}
            )
            for action in actions.copy():
                if isinstance(action['permissions'], dict):
                    action['permissions'] = action['permissions']['actions']
                for action in action['permissions']:
                    if action in all_actions and not action in permissions:
                        permissions.append(action)

        users = await server.auth_users.select('username', 'groups')
        for user in users.copy():
            if isinstance(user['groups'], dict):
                user['groups'] = user['groups']['groups']
        users = [user['username'] for user in users if group_name in user['groups']]

        roles_in_group = [
            (role, True) for role in roles] + [
            (role, False) for role in all_roles if not role in roles
        ]
        update_form = forms.get_form(
            f'Update {group_name}',
            [
                html_input.get_text_input("group_name", value=group_name),
                html_input.get_checkbox(
                    'roles',
                    roles_in_group,
                    size=12
                ) if len(roles_in_group) > 0 else "No Roles"
            ],
            submit_name='update group',
            method='post',
            action=f'/auth/group/{group_name}',
            transform_id=f'Update{group_name}'
        )

        modal_row = row.get_row(
            card.get_card(
                f'{group_name}',
                update_form,
                size=12
            )+
            card.get_card(
                f"Users",
                ''.join([
                    buttons.get_button(
                        user,
                        color='success', 
                        href=f'#{user}',
                        onclick=f"OnClickUpdate('{admin_prefix}/user/{user}', 'page-top')"
                    ) for user in users
                ]),
                size=4
            )+
            card.get_card(
                f"Roles",
                ''.join([
                    buttons.get_button(
                        role,
                        color='success', 
                        href=f'#{role}',
                        onclick=f"OnClickUpdate('{admin_prefix}/role/{role}', 'page-top')"
                    ) for role in roles
                ]),
                size=4
            )+
            card.get_card(
                f"Actions",
                ''.join([
                    buttons.get_button(
                        action,
                        color='success', 
                        href=f'#{action}',
                        onclick=f"OnClickUpdate('{admin_prefix}/action/{action}', 'page-top')"
                    ) for action in permissions
                ]),
                size=4
            )
        )
        return modal_row


    @admin_gui.get('/group/{group_name}', response_class=HTMLResponse, send_token=True, include_in_schema=False)
    async def admin_group_page(group_name: str, access_token: str = None):
        group = await server.auth_groups.select(
            '*', where={'group_name': group_name}
        )
        if not group:
            raise HTTPException(
                status_code=404,
                detail=f"No Group with name {group_name} exists"
            )

        group_page = admin.get_admin_page(
            name=group, 
            sidebar=server.admin.sidebar,
            body=await get_group_details(group_name),
            current_user=access_token['permissions']['users'][0],
            modals=logout_modal,
            google=await server.get_google_oauth_client_id()
        )
        return group_page

    @admin_gui.get('/groups', response_class=HTMLResponse, send_token=True, include_in_schema=False)
    async def admin_groups(access_token=None):
        groups = await server.auth_groups.select('*')

        groups = groups.copy()
        roles = await server.auth_roles.select('role')

        roles = deepcopy([role['role'] for role in roles])
        modals = [logout_modal]

        groups_table = deepcopy(groups)
        for ind, group in enumerate(groups):
            group_name = group['group_name']
            if isinstance(group['roles'], dict):
                group['roles'] = group['roles']['roles']
                modals.append(modal.get_modal(
                    f'delete{group_name}Modal',
                    alert='',
                    body=forms.get_form(
                        f'Delete Group {group_name}',
                        [
                            buttons.get_button(
                                'Go Back',
                                color='success', 
                                href=f'{admin_prefix}/groups'
                        )],
                        submit_name='delete group',
                        method='delete',
                        action=f'/auth/group?group_name={group_name}'
                    ),
                    footer='',
                    size='sm'
                )
            )
            modals.append(modal.get_modal(
                f'view_{group_name}',
                alert='',
                body=await get_group_details(group_name),
                footer='',
                size='lg'
            ))
            groups_table[ind]['roles'] = ''.join([
                buttons.get_button(
                    role,
                    color='success', 
                    href=f'{admin_prefix}/role/{role}')
                for role in group['roles'] if role in roles
            ])

            actions = ( 
                buttons.get_split_button(
                    f'view/edit',
                    icon='eye',
                    modal=f'view_{group_name}'
                ) + 
                buttons.get_split_button(
                    f'delete',
                    color='danger',
                    modal=f'delete{group_name}Modal',
                    icon='trash'
                )
            )
            groups_table[ind][' '] = actions

        admin_table =  server.admin.table_page(
            'Groups',
            groups_table if len(groups_table) > 0 else [{'group_name': 'NO GROUPS', 'roles': ''}],
            current_user=access_token['permissions']['users'][0],
            modals=''.join(modals),
            above="",
            below=forms.get_form(
                'Create Group',
                [
                    html_input.get_text_input("group_name"),
                    html_input.get_checkbox(
                        'roles', 
                        [(role, False) for role in roles],
                        size=12
                    )
                ],
                submit_name='create group',
                method='put',
                action='/auth/group'
            ),
            google=await server.get_google_oauth_client_id()
        )
        return admin_table


    async def get_role_details(role_name: str):
        role = await server.auth_roles.select(
            '*', where={'role': role_name}
        )
        if not role:
            raise HTTPException(
                status_code=404,
                detail=f"No Role with name {role_name} exists"
            )
        role = role[0]

        permissions = role['permissions']['actions'] if isinstance(role['permissions'], dict) else role['permissions']
        all_actions = await server.auth_actions.select('action')
        all_actions = [action['action'] for action in all_actions]

        permissions = [action for action in permissions if action in all_actions]

        all_groups = await server.auth_groups.select('group_name', 'roles')
        for group in all_groups.copy():
            if isinstance(group['roles'], dict):
                group['roles'] = group['roles']['roles']

        groups = [group['group_name'] for group in all_groups if role_name in group['roles']]

        all_users = await server.auth_users.select('username', 'groups')
        users = []
        for user in all_users.copy():
            if isinstance(user['groups'], dict):
                user['groups'] = user['groups']['groups']
        for user in all_users:
            for group in user['groups']:
                if group in groups:
                    users.append(user['username'])
                    break
        actions_in_role = [
            (action, True) for action in permissions] + [
            (action, False) for action in all_actions if not action in permissions
        ]
        update_form = forms.get_form(
            f'Update {role_name}',
            [
                html_input.get_text_input("role", value=role_name),
                html_input.get_checkbox(
                    'actions', 
                    actions_in_role,
                    size=12
                ) if len(actions_in_role) > 0 else "no actions"
            ],
            submit_name='update role',
            method='post',
            action=f'/auth/role/{role_name}',
            transform_id=f'Update{role_name}'
        )

        modal_row = row.get_row(
            card.get_card(
                f'{role_name}',
                update_form,
                size=12
            )+
            card.get_card(
                f"Users",
                ''.join([
                    buttons.get_button(
                        user,
                        color='success', 
                        href=f'#{user}',
                        onclick=f"OnClickUpdate('{admin_prefix}/user/{user}', 'page-top')"
                    ) for user in users
                ]),
                size=4
            )+
            card.get_card(
                f"Groups",
                ''.join([
                    buttons.get_button(
                        group,
                        color='success', 
                        href=f'#{group}',
                        onclick=f"OnClickUpdate('{admin_prefix}/group/{group}', 'page-top')"
                    ) for group in groups
                ]),
                size=4
            )+
            card.get_card(
                f"Actions",
                ''.join([
                    buttons.get_button(
                        action,
                        color='success', 
                        href=f'#{action}',
                        onclick=f"OnClickUpdate('{admin_prefix}/action/{action}', 'page-top')"
                    ) for action in permissions
                ]),
                size=4
            )
        )
        return modal_row

    @admin_gui.get('/role/{role_name}', response_class=HTMLResponse, send_token=True, include_in_schema=False)
    async def admin_role_page(role_name: str, access_token=None):
        role = await server.auth_roles.select(
            'role', where={'role': role_name}
        )
        if not role:
            raise HTTPException(
                status_code=404,
                detail=f"No Role with name {role_name} exists"
            )
        role_page = admin.get_admin_page(
            name=role_name, 
            sidebar=server.admin.sidebar,
            body=await get_role_details(role_name),
            current_user=access_token['permissions']['users'][0],
            modals=logout_modal,
            google=await server.get_google_oauth_client_id()
        )
        return role_page
        

    @admin_gui.get('/roles', response_class=HTMLResponse, send_token=True, include_in_schema=False)
    async def admin_roles(access_token=None):
        roles = await server.auth_roles.select('*')
        roles = roles.copy()
        permissions = await server.auth_actions.select('action')
        permissions = [action['action'] for action in permissions]
        modals = [logout_modal]
        for role in roles:
            role_name = role['role']
            modals.append(modal.get_modal(
                f'delete{role_name}Modal',
                alert='',
                body=forms.get_form(
                    f'Delete Role {role_name}',
                    [
                        buttons.get_button(
                            'Go Back',
                            color='success', 
                            href=f'{admin_prefix}/groups'
                    )],
                    submit_name='delete role',
                    method='delete',
                    action=f'/auth/role?role={role_name}'
                ),
                footer='',
                size='sm'
            ))
            modals.append(modal.get_modal(
                f'view_{role_name}',
                alert='',
                body=await get_role_details(role_name),
                footer='',
                size='lg'
            ))
            role['permissions'] = role['permissions']['actions']
            role['permissions'] = ''.join([
                buttons.get_button(
                    action,
                    color='success', 
                    href=f'{admin_prefix}/action/{action}')
                for action in role['permissions'] if action in permissions
            ])

            actions = ( 
                    buttons.get_split_button(
                        f'view/edit',
                        icon='eye',
                        modal=f'view_{role_name}'
                    ) + 
                    buttons.get_split_button(
                        f'delete', 
                        modal=f'delete{role_name}Modal', 
                        color='danger',
                        icon='trash'
                    )
                )
            role[' '] = actions
        admin_table = server.admin.table_page(
            'Roles',
            roles if len(roles) > 0 else [{'role': 'no roles', 'actions': ''}],
            current_user=access_token['permissions']['users'][0],
            modals=''.join(modals),
            above="",
            below=forms.get_form(
                'Create Role',
                [
                    html_input.get_text_input("role"),
                    html_input.get_checkbox(
                        'permissions', 
                        [(action, False) for action in permissions],
                        size=12
                    )
                ],
                submit_name='create role',
                method='put',
                action='/auth/role'
            ),
            google=await server.get_google_oauth_client_id()
        )
        _roles = await server.auth_roles.select('*')

        return admin_table

    async def get_action_details(action: str):
        permission = await server.auth_actions.select(
            '*', where={'action': action}
        )
        permission = permission.copy()
        if not permission:
            raise HTTPException(
                status_code=404,
                detail=f"No permission with name {action} exists"
            )
        permission = permission[0]

        all_roles = await server.auth_roles.select('*')
        for role in all_roles.copy():
            if isinstance(role['permissions'], dict):
                role['permissions'] = role['permissions']['actions']
        
        roles = []
        for role in all_roles:
            if permission['action'] in role['permissions']:
                roles.append(role['role'])
                break
        
        all_groups = await server.auth_groups.select('group_name', 'roles')
        for group in all_groups.copy():
            if isinstance(group['roles'], dict):
                group['roles'] = group['roles']['roles']
        groups = []
        for group in all_groups:
            for role in group['roles']:
                if role in roles:
                    groups.append(group['group_name'])
                    break

        all_users = await server.auth_users.select('username', 'groups')
        users = []
        for user in all_users.copy():
            if isinstance(user['groups'], dict):
                user['groups'] = user['groups']['groups']
        for user in all_users:
            for group in user['groups']:
                if group in groups:
                    users.append(user['username'])
                    break
                
        update_form = forms.get_form(
            f'Update {action}',
            [
                html_input.get_text_input("action", value=action),
                html_input.get_text_input("details", value=permission['details'])
            ],
            submit_name='update permission',
            method='post',
            action='/auth/permissions',
            transform_id=f'Update{action}'
        )

        modal_row = row.get_row(
            card.get_card(
                f'{action}',
                update_form,
                size=12
            )+
            card.get_card(
                f"Users",
                ''.join([
                    buttons.get_button(
                        user,
                        color='success', 
                        href=f'#{user}',
                        onclick=f"OnClickUpdate('{admin_prefix}/user/{user}', 'page-top')"
                    ) for user in users
                ]),
                size=4
            )+
            card.get_card(
                f"Groups",
                ''.join([
                    buttons.get_button(
                        group,
                        color='success', 
                        href=f'#{group}',
                        onclick=f"OnClickUpdate('{admin_prefix}/group/{group}', 'page-top')"
                    ) for group in groups
                ]),
                size=4
            )+
            card.get_card(
                f"Roles",
                ''.join([
                    buttons.get_button(
                        role,
                        color='success', 
                        href=f'#{role}',
                        onclick=f"OnClickUpdate('{admin_prefix}/role/{role}', 'page-top')"
                    ) for role in roles
                ]),
                size=4
            )
        )
        return modal_row
    @admin_gui.get('/action/{action}', response_class=HTMLResponse, send_token=True, include_in_schema=False)
    async def admin_action_page(action: str, access_token=None):
        permission = await server.auth_actions.select(
            '*', where={'action': action}
        )
        if not permission:
            raise HTTPException(
                status_code=404,
                detail=f"No permission with name {action} exists"
            )
        action_page = admin.get_admin_page(
            name=action, 
            sidebar=server.admin.sidebar,
            body=await get_action_details(action),
            current_user=access_token['permissions']['users'][0],
            modals=logout_modal,
            google=await server.get_google_oauth_client_id()
        )
        return action_page

    @admin_gui.get('/actions', response_class=HTMLResponse, send_token=True, include_in_schema=False)
    async def admin_actions(access_token=None):
        permissions = await server.auth_actions.select('*')
        modals = [logout_modal]
        for permission in permissions:
            action = permission['action']
            modals.append(modal.get_modal(
                    f'delete{action}Modal',
                    alert='',
                    body=forms.get_form(
                        f'Delete Action {action}',
                        [
                            buttons.get_button(
                                'Go Back',
                                color='success', 
                                href=f'{admin_prefix}/actions'
                        )],
                        submit_name='delete action',
                        method='delete',
                        action=f'/auth/permission?action={action}'
                    ),
                    footer='',
                    size='sm'
                )
            )
            modals.append(modal.get_modal(
                f'view_{action}',
                alert='',
                body=await get_action_details(action),
                footer='',
                size='lg'
            ))
            actions = ( 
                buttons.get_split_button(
                    f'view / edit',
                    icon='eye',
                    modal=f'view_{action}'
                ) + 
                buttons.get_split_button(
                    f'delete', 
                    modal=f'delete{action}Modal', 
                    color='danger',
                    icon='trash'
                )
            )
            permission[' '] = actions
        return server.admin.table_page(
            'Permissions',
            permissions if len(permissions) > 0 else [{'action': 'NO_ACTIONS', 'details': ''}],
            current_user=access_token['permissions']['users'][0],
            modals=''.join(modals),
            above="",
            below=forms.get_form(
                'Create Permission',
                [
                    html_input.get_text_input("action"),
                    html_input.get_text_input("details"),
                ],
                submit_name='create permission',
                method='put',
                action='/auth/permissions'
            ),
            google=await server.get_google_oauth_client_id()
        )
    

    def get_token_details(token: dict):
        
        users = token['users'] if 'users' in token else []
        groups = token['groups'] if 'groups' in token else []
        roles = token['roles'] if 'roles' in token else []
        actions = token['actions'] if 'actions' in token else []

        modal_row = card.get_card(
            f"{users[0]} Token Permissions",
            body = row.get_row(
                card.get_card(
                    f"Users",
                    ''.join([
                        buttons.get_button(
                            user,
                            color='success', 
                            href=f'#{user}',
                            onclick=f"OnClickUpdate('{admin_prefix}/user/{user}', 'page-top')"
                        ) for user in users
                    ]),
                    size=4
                )+
                card.get_card(
                    f"Groups",
                    ''.join([
                        buttons.get_button(
                            group,
                            color='success', 
                            href=f'#{group}',
                            onclick=f"OnClickUpdate('{admin_prefix}/group/{group}', 'page-top')"
                        ) for group in groups
                    ]),
                    size=4
                )+
                card.get_card(
                    f"Roles",
                    ''.join([
                        buttons.get_button(
                            role,
                            color='success', 
                            href=f'#{role}',
                            onclick=f"OnClickUpdate('{admin_prefix}/role/{role}', 'page-top')"
                        ) for role in roles
                    ]),
                    size=4
                )+
                card.get_card(
                    f"Actions",
                    ''.join([
                        buttons.get_button(
                            action,
                            color='success', 
                            href=f'#{action}',
                            onclick=f"OnClickUpdate('{admin_prefix}/action/{action}', 'page-top')"
                        ) for action in actions
                    ]),
                    size=4
                )
            ),
            size=12
        )
        return modal_row
    
    @admin_gui.get('/tokens', response_class=HTMLResponse, send_token=True, include_in_schema=False)
    async def admin_tokens(access_token=None):
        tokens_raw = await server.auth_tokens.select('*')
        DO_NOT_DISPLAY = {'token_id', 'token'}

        tokens = []
        for ind, token in enumerate(tokens_raw):
            tk = {'number': ind}
            for k,v in token.items():
                if k in DO_NOT_DISPLAY:
                    continue
                tk[k] = v
            tokens.append(tk)
                
    
        modals = [logout_modal]
        token_index = {}
        for token in tokens:
            token_number = token['number']
            token_id = tokens_raw[token_number]['token_id']
            token_user = sub('[@.]', '', token['username'])
            modals.append(modal.get_modal(
                    f'revoke{token_number}Modal',
                    alert='',
                    body=forms.get_form(
                        f"Revoke Token {token_number} for {token_user}",
                        [
                            buttons.get_button(
                                'Go Back',
                                color='success', 
                                href=f'{admin_prefix}/tokens'
                        )],
                        submit_name='revoke token',
                        method='delete',
                        action=f'/auth/token?token_id={token_id}'
                    ),
                    footer='',
                    size='sm'
                )
            )
            token_details = tokens_raw[token_number]['token']
            modals.append(modal.get_modal(
                f'view_{token_number}',
                alert='',
                body=get_token_details(token_details),
                footer='',
                size='lg'
            ))
            actions = ( 
                buttons.get_split_button(
                    f'view',
                    icon='eye',
                    modal=f'view_{token_number}'
                ) + 
                buttons.get_split_button(
                    f'revoke', 
                    modal=f'revoke{token_number}Modal', 
                    color='danger',
                    icon='trash'
                )
            )
            token[' '] = actions
        return server.admin.table_page(
            'Tokens',
            tokens if len(tokens) > 0 else [
                {
                    'username': 'NO USER ISSUED TOKENS', 
                    'issued': '',
                    'expiration': ''
                }
            ],
            current_user=access_token['permissions']['users'][0],
            modals=''.join(modals),
            above="",
            below='',
            google=await server.get_google_oauth_client_id()
        )

    @admin_gui.get('/email', response_class=HTMLResponse, send_token=True, include_in_schema=False)
    async def admin_email(access_token=None):
        modals = []
        modals.append(
            modal.get_modal(
                f'SendTestEmailModal',
                alert='',
                body=forms.get_form(
                    f'Send A Test Email',
                    [
                        html_input.get_text_input("subject"),
                        html_input.get_text_input("recipients"),
                        html_input.get_text_input("email_body"),
                    ],
                    submit_name=f'send email',
                    method='post',
                    action=f'/email/send?test_email=true',
                    transform_id='SendATestEmail'
                ),
                footer='',
                size='large'
            )
        )


        email_config = await server.db.tables['email_config'].select('*')
        MAIL_USERNAME = email_config[0]['username'] if email_config else ''
        MAIL_FROM = email_config[0]['mail_from'] if email_config else ''
        MAIL_FROM_NAME = email_config[0]['mail_from_name'] if email_config else ''
        MAIL_SERVER = email_config[0]['server'] if email_config else ''
        MAIL_PORT = email_config[0]['port'] if email_config else ''
        MAIL_SSL = email_config[0]['mail_ssl'] if email_config else ''
        MAIL_TLS = email_config[0]['mail_tls'] if email_config else ''
        SEND_ACTIVATION_EMAILS = email_config[0]['send_activation_emails'] if email_config else ''

        return server.admin.admin_page(
            'Email Configuration',
            body=forms.get_form(
                'Configure Email',
                [
                    html_input.get_text_input("MAIL_USERNAME", value=MAIL_USERNAME)+
                    html_input.get_text_input("MAIL_PASSWORD", input_type='password'),
                    html_input.get_text_input("MAIL_FROM", value=MAIL_FROM) +
                    html_input.get_text_input("MAIL_FROM_NAME", value=MAIL_FROM_NAME),
                    html_input.get_text_input("MAIL_SERVER", value=MAIL_SERVER)+
                    html_input.get_text_input("MAIL_PORT", value=MAIL_PORT),
                    html_input.get_checkbox('MAIL_SSL', [('MAIL_SSL', MAIL_SSL)]) +
                    html_input.get_checkbox('MAIL_TLS', [('MAIL_TLS', MAIL_TLS)])+
                    html_input.get_checkbox('SEND_ACTIVATION_EMAILS', [('SEND_ACTIVATION_EMAILS', SEND_ACTIVATION_EMAILS)]),
                ],
                submit_name='configure email',
                method='post',
                action='/email/setup',
                transform_id=f'ConfigureEmail',
            )+
            buttons.get_split_button(
                f'Send Test Email',
                icon='envelope',
                modal=f'SendTestEmailModal'
            ),
            current_user=access_token['permissions']['users'][0],
            modals=''.join(modals),
            google=await server.get_google_oauth_client_id() 
        )

    @server.server.get('/login', response_class=HTMLResponse, tags=['Login'])
    async def admin_login(request: Request):
        # present enabled oauth login options
        return await server.get_login_page(
            message='Login to begin',
            request=request
        )

    @server.server.get('/register', response_class=HTMLResponse, tags=['User'])
    async def admin_register():
        return register.get_register_user_page(
            form = forms.get_form(
                title='Register User',
                rows=[
                    html_input.get_text_input('username', size=12),
                    html_input.get_text_input('password', input_type='password',  size=12),
                    html_input.get_text_input('repeat password', input_type='password',  size=12),
                    html_input.get_text_input('full name', size=12),
                    html_input.get_text_input('email address', size=12)
                ],
                submit_name='Register User',
                action="/auth/user/register",
                transform_id='RegisterUser'
            )
        )
    @server.server.get('/activate', response_class=HTMLResponse, tags=['User'])
    async def admin_activate():
        return register.get_register_user_page(
            title='Activate user',
            welcome_message='Activate your account',
            form = forms.get_form(
                title='Activate User',
                rows=[
                    html_input.get_text_input('activation_code', size=12)
                ],
                submit_name='Activate',
                action="/auth/user/activate",
                transform_id='ActivateUser'
            )
        )

    @admin_gui.get('/oauth', response_class=HTMLResponse, send_token=True, include_in_schema=False)
    async def admin_oauth(access_token=None):

        groups = await server.auth_groups.select('group_name')
        groups = deepcopy([group['group_name'] for group in groups])

        oauth_config = await server.db.tables['oauth'].select('*')

        oauth_forms = []

        for config in oauth_config:
            provider = config['provider']
            default_groups = html_input.get_checkbox(
                'default_groups', 
                [(group, group in config['default_groups']['default_groups']) for group in deepcopy(groups)],
                size=12,
                unique_id=provider
            )

            oauth_forms.append(
                forms.get_form(
                    f"{provider} OAuth",
                    [
                        html_input.get_text_input("client_id", value=config['client_id']),
                        html_input.get_checkbox('enabled', [('enabled', config['enabled'])]),
                        default_groups,
                    ],
                    submit_name=f'Update {provider} OAuth',
                    method='post',
                    action=f'/auth/oauth/{provider}',
                    transform_id=f'{provider}OAuth'
                )
            )

        return server.admin.admin_page(
            'Identity Providers',
            body=''.join(oauth_forms),
            current_user=access_token['permissions']['users'][0],
            modals=logout_modal,
            google=await server.get_google_oauth_client_id()
        )