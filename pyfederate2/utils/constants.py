from typing import Literal, Annotated
from fastapi import status
from enum import Enum
from fastapi import Header


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
    NONE = "none"
    CLIENT_SECRET_POST = "client_secret_post"
    PRIVATE_KEY_JWT = "private_key_jwt"


class TokenModelType(Enum):
    JWT = "jwt"
    OPAQUE = "opaque"


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


BEARER_TOKEN_TYPE = "Bearer"
JWK_IDS_LITERAL = Literal[tuple(PRIVATE_JWKS.keys())]  # type: ignore
CORRELATION_ID_HEADER_TYPE = Annotated[
    str | None,
    Header(
        alias=HTTPHeaders.X_CORRELATION_ID.value,
        description="ID that will added in the logs to help debugging.",
    ),
]
