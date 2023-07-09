from enum import Enum

class GrantType(Enum):
    CLIENT_CREDENTIALS = "client_credentials"
    AUTHORIZATION_CODE = "authorization_code"
    REFRESH_TOKEN = "refresh_token"

class TokenType(Enum):
    BEARER = "bearer"

class ErrorCode(Enum):
    ACCESS_DENIED = "access_denied"

class Config:
    CLIENT_SECRET_LENGH: int = 30