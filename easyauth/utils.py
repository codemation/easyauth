import jwt
from fastapi import Depends, Request


def get_user():
    def get_user_handler(request: Request):
        if "token" not in request.cookies and "Authorization" not in request.headers:
            return None

        if "token" in request.cookies:
            try:
                decoded_token = jwt.decode(
                    request.cookies["token"], options={"verify_signature": False}
                )
                return decoded_token["permissions"]["users"][0]
            except jwt.exceptions.DecodeError:
                return None
        elif "Authorization" in request.headers:
            # header should be separated by 'Bearer <tokenstr>'
            decoded_token = jwt.decode(
                request.headers["Authorization"].split(" ")[1],
                options={"verify_signature": False},
            )
            return decoded_token["permissions"]["users"][0]
        return None

    return Depends(get_user_handler)
