from typing import Dict, Literal, Annotated
from dataclasses import dataclass
from enum import Enum
import logging
import json
import os
from fastapi import Header
import base64
import os
from dotenv import load_dotenv

load_dotenv()

########## Enumerations ##########

class HTTPHeaders(Enum):
    CACHE_CONTROL = "Cache-Control"
    LOCATION = "location"
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

class AuthnStatus(Enum):
    IN_PROGRESS = "in_progress"
    FAILURE = "failure"
    SUCCESS = "success"

########## Configurations ##########
LOG_LEVEL = logging.getLevelName(os.environ.get("LOG_LEVEL", "DEBUG"))
CLIENT_ID_MIN_LENGH = int(os.getenv("CLIENT_ID_MIN_LENGH", 20))
CLIENT_ID_MAX_LENGH = int(os.getenv("CLIENT_ID_MAX_LENGH", 25))
CLIENT_SECRET_MIN_LENGH = int(os.getenv("CLIENT_SECRET_MIN_LENGH", 45))
CLIENT_SECRET_MAX_LENGH = int(os.getenv("CLIENT_SECRET_MAX_LENGH", 50))
CALLBACK_ID_LENGTH = int(os.getenv("CALLBACK_ID_LENGTH", 20))
SESSION_ID_LENGTH = int(os.getenv("SESSION_ID_LENGTH", 20))
AUTHORIZATION_CODE_LENGTH = int(os.getenv("AUTHORIZATION_CODE_LENGTH", 20))
STATE_PARAM_MAX_LENGTH = int(os.getenv("STATE_PARAM_MAX_LENGTH", 100))
SECRET_ENCODING = os.getenv("SECRET_ENCODING", "utf-8")
BEARER_TOKEN_TYPE = "bearer"

@dataclass
class JWKInfo:
    key_id: str
    key: str
    signing_algorithm: str

# Load the privates JWKs
PRIVATE_JWKS: Dict[
    str, JWKInfo
] = {
    key["kid"]: JWKInfo(
        key_id=key["kid"],
        key=key["k"],
        signing_algorithm=key["alg"]
    ) for key in json.loads(
        # The privates jwks are passed as a base64 enconded json through the env var PRIVATE_JWKS_JSON
        base64.b64decode(os.environ["PRIVATE_JWKS_JSON"]).decode(SECRET_ENCODING)
    )["keys"]
}

########## Type Hints ##########
JWK_IDS_LITERAL = Literal[tuple(PRIVATE_JWKS.keys())] # type: ignore
CORRELATION_ID_HEADER_TYPE = Annotated[str | None, Header(alias=HTTPHeaders.X_CORRELATION_ID.name)]