### Database Usage
!!! TIP 
    The default 'batteries mostly included' implementation utilizes a sqlite database managed by aiopyql.

!!! INFO "Supported Databases"
    - sqlite
    - mysql
    - postgres
#### Preparing a env.json
```bash
cat > server_env.json << EOF
{
    "DB_TYPE": "mysql",
    "DB_NAME": "auth",
    "DB_HOST": "0.0.0.0",
    "DB_PORT": "3306",
    "DB_USER": "mysqluser",
    "DB_PASSWORD": "my-secret",
    "ISSUER": "EasyAuth",
    "SUBJECT": "EasyAuthAuth",
    "AUDIENCE": "EasyAuthApis",
    "KEY_PATH": "/home/josh/Documents/python/EasyAuth/EasyAuth",
    "KEY_NAME": "test_key"
}
EOF
```