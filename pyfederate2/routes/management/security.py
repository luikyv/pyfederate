from typing import Annotated
from fastapi import Depends
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import secrets

######################################## Credentials ########################################

security = HTTPBasic()


def validate_credentials(
    credentials: Annotated[HTTPBasicCredentials, Depends(security)]
) -> None:

    correct_username_bytes = b"admin"
    correct_password_bytes = b"password"

    current_username_bytes = credentials.username.encode("utf8")
    is_correct_username = secrets.compare_digest(
        current_username_bytes, correct_username_bytes
    )
    current_password_bytes = credentials.password.encode("utf8")
    is_correct_password = secrets.compare_digest(
        current_password_bytes, correct_password_bytes
    )
    if not (is_correct_username and is_correct_password):
        raise exceptions.JsonResponseException(
            error=constants.ErrorCode.NOT_UNAUTHORIZED,
            error_description="invalid credentials",
        )
