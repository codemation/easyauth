from fastapi import HTTPException


class DuplicateUserError(HTTPException):
    def __init__(self, username: str):
        super().__init__(
            status_code=422, detail=f"A user with name {username} already exists"
        )


class InvalidActivationCode(HTTPException):
    def __init__(self, username: str):
        super().__init__(status_code=404, detail="Invalid activation code provided")


class InvalidUsernameOrPassword(HTTPException):
    def __init__(self):
        super().__init__(
            status_code=401, detail="Invalid Username or Password provided"
        )


class GoogleOauthNotEnabledOrConfigured(HTTPException):
    def __init__(self):
        super().__init__(
            status_code=503,
            detail="Google authentication is not enabled or configured",
        )


class GoogleOauthHeaderMalformed(HTTPException):
    def __init__(self):
        super().__init__(
            status_code=503, detail="Expected 'X-Google-OAuth2-Type' in header"
        )


class EasyAuthClientToServerConnectionError(Exception):
    def __init__(self, server, port):
        super().__init__(self, f"Connection to EasyAuthServer {server}:{port} failed")
