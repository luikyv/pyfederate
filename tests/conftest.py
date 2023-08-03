from typing import TypeVar
import pytest

from auth_server.utils import schemas, tools, constants

ISSUER = "https://authorization-server.com/"
CLIENT_ID = "client_id"
CLIENT_SECRET = "cGxa8HdCHBRnD6AkOT17RrQvgdEuJRXU4zgpQQczVJJ26"
HASHED_CLIENT_SECRET = "$2b$12$PXi6674c78E9KMYrmxLCOOVAi5Rlw7P.paqlQaye7CfuM3VdTP7nG"
TOKEN_EXPIRATION = 300
SCOPES = ["scope1", "scope2"]
REDIRECT_URI = "https://localhost:8080/callback"
SUBJECT = "user@email.com"
TOKEN_ID = "token_id"
TOKEN_MODEL_ID = "token_model_id"
KEY_ID = "key_id"
HMAC_SIGNING_KEY = "A0b6789SDbj78jFJH43f345"

timestamp_now: int = tools.get_timestamp_now()
token_info = schemas.TokenInfo(
    subject=SUBJECT,
    issuer=ISSUER,
    issued_at=timestamp_now,
    expiration=timestamp_now + TOKEN_EXPIRATION,
    client_id=CLIENT_ID,
    scopes=SCOPES,
    id=TOKEN_ID,
    additional_info={}
)

expected_jwt_payload = {
    "sub": SUBJECT,
    "iss": ISSUER,
    "iat": timestamp_now,
    "exp": timestamp_now + TOKEN_EXPIRATION,
    "client_id": CLIENT_ID,
    "jti": TOKEN_ID,
    "scope": " ".join(SCOPES),
}

jwt_token_model = schemas.JWTTokenModel(
    id=TOKEN_MODEL_ID,
    issuer=ISSUER,
    expires_in=TOKEN_EXPIRATION,
    is_refreshable=True,
    key_id=KEY_ID,
    key=HMAC_SIGNING_KEY,
    signing_algorithm=constants.SigningAlgorithm.HS256
)


@pytest.fixture
def client() -> schemas.Client:
    return schemas.Client(
        id=CLIENT_ID,
        authn_method=constants.ClientAuthnMethod.CLIENT_SECRET_POST,
        redirect_uris=[REDIRECT_URI],
        response_types=[constants.ResponseType.CODE],
        grant_types=[constants.GrantType.AUTHORIZATION_CODE],
        scopes=SCOPES,
        token_model=jwt_token_model,
        is_pkce_required=False,
        hashed_secret=HASHED_CLIENT_SECRET
    )


client_in = schemas.ClientIn(
    id=CLIENT_ID,
    authn_method=constants.ClientAuthnMethod.CLIENT_SECRET_POST,
    redirect_uris=[REDIRECT_URI],
    response_types=[constants.ResponseType.CODE],
    grant_types=[constants.GrantType.AUTHORIZATION_CODE],
    scopes=SCOPES,
    token_model_id=TOKEN_MODEL_ID,
    is_pkce_required=True,
)

T = TypeVar("T")


async def async_return(o: T) -> T:
    return o
