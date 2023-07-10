from enum import Enum

########## Enumerations ##########

class GrantType(Enum):
    CLIENT_CREDENTIALS = "client_credentials"
    AUTHORIZATION_CODE = "authorization_code"
    REFRESH_TOKEN = "refresh_token"

class TokenType(Enum):
    BEARER = "bearer"

class ErrorCode(Enum):
    ACCESS_DENIED = "access_denied"

########## Configurations ##########

DATABASE_URL = "sqlite:///./sql_app.db"
CLIENT_ID_LENGH = 20
CLIENT_SECRET_LENGH = 30
SECRET_ENCODING = "utf-8"