from typing import Dict, Literal, Annotated
from dataclasses import dataclass
from fastapi import status
from enum import Enum
import logging
import json
import os
from fastapi import Header
import base64
from dotenv import load_dotenv

########## Enumerations ##########


class Environment(Enum):
    PROD = "PROD"
    TEST = "TEST"
    LOCAL = "LOCAL"


class HTTPHeaders(Enum):
    CACHE_CONTROL = "Cache-Control"
    PRAGMA = "Pragma"
    LOCATION = "location"
    X_CORRELATION_ID = "X-Correlation-ID"


class GrantType(Enum):
    CLIENT_CREDENTIALS = "client_credentials"
    AUTHORIZATION_CODE = "authorization_code"
    REFRESH_TOKEN = "refresh_token"


class ResponseType(Enum):
    CODE = "code"
    ID_TOKEN = "id_token"


class TokenType(Enum):
    JWT = "jwt"


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


class CodeChallengeMethod(Enum):
    S256 = "S256"


class ClientAuthnMethod(Enum):
    CLIENT_SECRET_POST = "client_secret_post"
    NONE = "none"


class ErrorCode(Enum):
    ACCESS_DENIED = status.HTTP_403_FORBIDDEN
    INVALID_REQUEST = status.HTTP_400_BAD_REQUEST
    INVALID_CLIENT = status.HTTP_400_BAD_REQUEST
    INVALID_GRANT = status.HTTP_400_BAD_REQUEST
    INVALID_SCOPE = status.HTTP_400_BAD_REQUEST
    UNAUTHORIZED_CLIENT = status.HTTP_401_UNAUTHORIZED
    NOT_UNAUTHORIZED = status.HTTP_401_UNAUTHORIZED


class AuthnStatus(Enum):
    IN_PROGRESS = "in_progress"
    FAILURE = "failure"
    SUCCESS = "success"


########## Configurations ##########
ENVIRONMENT = Environment(os.getenv("ENVIRONMENT", "LOCAL"))
if ENVIRONMENT == Environment.LOCAL:
    load_dotenv()
elif ENVIRONMENT == Environment.TEST:
    load_dotenv("tests/test.env")
LOG_LEVEL = logging.getLevelName(os.environ.get("LOG_LEVEL", "DEBUG"))
CLIENT_ID_MIN_LENGH = int(os.getenv("CLIENT_ID_MIN_LENGH", 5))
CLIENT_ID_MAX_LENGH = int(os.getenv("CLIENT_ID_MAX_LENGH", 50))
CLIENT_SECRET_MIN_LENGH = int(os.getenv("CLIENT_SECRET_MIN_LENGH", 10))
CLIENT_SECRET_MAX_LENGH = int(os.getenv("CLIENT_SECRET_MAX_LENGH", 50))
CALLBACK_ID_LENGTH = int(os.getenv("CALLBACK_ID_LENGTH", 20))
SESSION_ID_LENGTH = int(os.getenv("SESSION_ID_LENGTH", 20))
REFRESH_TOKEN_LENGTH = int(os.getenv("REFRESH_TOKEN_LENGTH", 20))
AUTHORIZATION_CODE_LENGTH = int(os.getenv("AUTHORIZATION_CODE_LENGTH", 20))
STATE_PARAM_MAX_LENGTH = int(os.getenv("STATE_PARAM_MAX_LENGTH", 100))
SECRET_ENCODING = os.getenv("SECRET_ENCODING", "utf-8")
AUTHORIZATION_CODE_TIMEOUT = int(os.getenv("AUTHORIZATION_SESSION_TIMEOUT", 300))
SERVER_PORT = int(os.getenv("SERVER_PORT", 8000))
BEARER_TOKEN_TYPE = "Bearer"


@dataclass
class JWKInfo:
    key_id: str
    key: str
    signing_algorithm: SigningAlgorithm


# Load the privates JWKs
PRIVATE_JWKS: Dict[str, JWKInfo] = {
    key["kid"]: JWKInfo(
        key_id=key["kid"], key=key["k"], signing_algorithm=SigningAlgorithm(key["alg"])
    )
    for key in json.loads(
        # The privates jwks are passed as a base64 enconded json through the env var PRIVATE_JWKS_JSON
        base64.b64decode(os.environ["PRIVATE_JWKS_JSON"]).decode(SECRET_ENCODING)
    )["keys"]
}

########## Type Hints ##########
JWK_IDS_LITERAL = Literal[tuple(PRIVATE_JWKS.keys())]  # type: ignore
CORRELATION_ID_HEADER_TYPE = Annotated[
    str | None,
    Header(
        alias=HTTPHeaders.X_CORRELATION_ID.value,
        description="ID that will added in the logs to help debugging",
    ),
]
