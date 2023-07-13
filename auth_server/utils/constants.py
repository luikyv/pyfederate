from dataclasses import dataclass
import typing
from enum import Enum
import logging
import json
import os

@dataclass
class JWKInfo:
    key_id: str
    key: str
    signing_algorithm: str

########## Configurations ##########

LOG_LEVEL = logging.DEBUG
DATABASE_URL = "sqlite:///./sql_app.db"
CLIENT_ID_LENGH = 20
CLIENT_SECRET_LENGH = 30
SECRET_ENCODING = "utf-8"
BEARER_TOKEN_TYPE = "bearer"

# Load the privates JWKs
with open(os.path.join(os.path.dirname(__file__), "..", "..", "private_jwks.json"), "r") as f:
    PRIVATE_JWKS: typing.Dict[
        str, JWKInfo
    ] = {key["kid"]: JWKInfo(
        key_id=key["kid"],
        key=key["k"],
        signing_algorithm=key["alg"]
    ) for key in json.load(f)["keys"]}

JWK_IDS_LITERAL = typing.Literal[tuple(PRIVATE_JWKS.keys())] # type: ignore

########## Enumerations ##########

class HTTPHeaders(Enum):
    CACHE_CONTROL = "Cache-Control"
    X_FLOW_ID = "X-Flow-ID"

class GrantType(Enum):
    CLIENT_CREDENTIALS = "client_credentials"
    AUTHORIZATION_CODE = "authorization_code"
    REFRESH_TOKEN = "refresh_token"

class ResponseType(Enum):
    CODE = "code"
    ID_TOKEN = "id_token"

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
    INVALID_REQUEST = "invalid_request"
    INVALID_CLIENT = "invalid_client"
    INVALID_GRANT = "invalid_grant"
    INVALID_SCOPE = "invalid_scope"