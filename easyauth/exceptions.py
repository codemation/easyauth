from fastapi import HTTPException

class DuplicateUserError(HTTPException):
    def __init__(self, username: str):
        super().__init__(
            status_code = 422,
            detail = f"A user with name {username} already exists"
        )

class InvalidActivationCode(HTTPException):
    def __init__(self, username: str):
        super().__init__(
            status_code = 404,
            detail = f"Invalid activation code provided"
        )
class InvalidUsernameOrPassword(HTTPException):
    def __init__(self):
        super().__init__(
            status_code = 401,
            detail = f"Invalid Username or Password provided"
        )