from enum import Enum
import logging

########## Configurations ##########

LOG_LEVEL = logging.DEBUG
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
    AUDIENCE = "aud"
    CLIENT_ID = "client_id"
    EXPIRATION = "exp"
    ISSUED_AT = "iat"
    ISSUER = "iss"
    JWT_ID = "jti"
    SUBJECT = "sub"
    SCOPE = "scope"

class SigningAlgorithm(Enum):
    HS256 = "HS256"
    RS256 = "RS256"

class ErrorCode(Enum):
    ACCESS_DENIED = "access_denied"