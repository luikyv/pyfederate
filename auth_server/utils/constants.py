from enum import Enum

########## Configurations ##########

DATABASE_URL = "sqlite:///./sql_app.db"
CLIENT_ID_LENGH = 20
CLIENT_SECRET_LENGH = 30
SECRET_ENCODING = "utf-8"
BEARER_TOKEN_TYPE = "bearer"
KEYS = {
    "my_key": "abcd"
}

########## Enumerations ##########

class GrantType(Enum):
    CLIENT_CREDENTIALS = "client_credentials"
    AUTHORIZATION_CODE = "authorization_code"
    REFRESH_TOKEN = "refresh_token"

class TokenType(Enum):
    JWT = "jwt"
    OPAQUE = "opaque"

class TokenClaim(Enum):
    SUBJECT = "sub"
    ISSUER = "iss"

class SigningAlgorithm(Enum):
    HS256 = "HS256"
    RS256 = "RS256"

class ErrorCode(Enum):
    ACCESS_DENIED = "access_denied"