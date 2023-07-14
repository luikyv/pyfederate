import typing
from dataclasses import dataclass
from enum import Enum
import logging
import json
import os
from fastapi import Header

########## Enumerations ##########

class HTTPHeaders(Enum):
    CACHE_CONTROL = "Cache-Control"
    X_CORRELATION_ID = "X-Correlation-ID"

class GrantType(Enum):
    CLIENT_CREDENTIALS = "client_credentials"
    AUTHORIZATION_CODE = "authorization_code"
    REFRESH_TOKEN = "refresh_token"

class ResponseType(Enum):
    CODE = "code"
    CODE_ID_TOKEN = "code id_token"

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

########## Configurations ##########

LOG_LEVEL = logging.DEBUG
DATABASE_URL = "sqlite:///./sql_app.db"
CLIENT_ID_MIN_LENGH = 20
CLIENT_ID_MAX_LENGH = 25
CLIENT_SECRET_MIN_LENGH = 45
CLIENT_SECRET_MAX_LENGH = 50
CALLBACK_ID_LENGTH = 20
AUTHORIZATION_CODE_LENGTH = 20
STATE_PARAM_MAX_LENGTH = 100
SECRET_ENCODING = "utf-8"
BEARER_TOKEN_TYPE = "bearer"

@dataclass
class JWKInfo:
    key_id: str
    key: str
    signing_algorithm: str

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
CORRELATION_ID_HEADER_TYPE = typing.Annotated[str | None, Header(alias=HTTPHeaders.X_CORRELATION_ID.name)]