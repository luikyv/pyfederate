from typing import TypeVar
import pytest

from auth_server.utils import schemas, tools, constants

######################################## Constants ########################################

ISSUER = "https://authorization-server.com/"
CLIENT_ID = "client_id"
CLIENT_SECRET = "cGxa8HdCHBRnD6AkOT17RrQvgdEuJRXU4zgpQQczVJJ26"
HASHED_CLIENT_SECRET = "$2b$12$PXi6674c78E9KMYrmxLCOOVAi5Rlw7P.paqlQaye7CfuM3VdTP7nG"
TOKEN_EXPIRATION = 300
SCOPES = ["scope1", "scope2"]
REDIRECT_URI = "https://localhost:8080/callback"
USER_ID = "user@email.com"
TOKEN_ID = "token_id"
TOKEN_MODEL_ID = "token_model_id"
KEY_ID = "key_id"
HMAC_SIGNING_KEY = "A0b6789SDbj78jFJH43f345"
SIGNING_ALGORITHM = constants.SigningAlgorithm.HS256
AUTHORIZATION_CODE = "authz_code"
CALLBACK_ID = "callback_id"
STATE = "random_state"
AUTHENTICATION_POLICY_ID = "authn_policy_id"

timestamp_now: int = tools.get_timestamp_now()


######################################## Fixtures ########################################

@pytest.fixture
def token_info() -> schemas.TokenInfo:
    return schemas.TokenInfo(
        subject=USER_ID,
        issuer=ISSUER,
        issued_at=timestamp_now,
        expiration=timestamp_now + TOKEN_EXPIRATION,
        client_id=CLIENT_ID,
        scopes=SCOPES,
        id=TOKEN_ID,
        additional_info={}
    )


@pytest.fixture
def jwt_token_model() -> schemas.JWTTokenModel:
    return schemas.JWTTokenModel(
        id=TOKEN_MODEL_ID,
        issuer=ISSUER,
        expires_in=TOKEN_EXPIRATION,
        is_refreshable=True,
        key_id=KEY_ID,
        key=HMAC_SIGNING_KEY,
        signing_algorithm=constants.SigningAlgorithm.HS256
    )


@pytest.fixture
def client(jwt_token_model: schemas.JWTTokenModel) -> schemas.Client:
    return schemas.Client(
        id=CLIENT_ID,
        authn_method=constants.ClientAuthnMethod.NONE,
        redirect_uris=[REDIRECT_URI],
        response_types=[constants.ResponseType.CODE],
        grant_types=[
            constants.GrantType.AUTHORIZATION_CODE,
            constants.GrantType.CLIENT_CREDENTIALS,
            constants.GrantType.REFRESH_TOKEN
        ],
        scopes=SCOPES,
        token_model=jwt_token_model,
        is_pkce_required=False,
        hashed_secret=None
    )


@pytest.fixture
def no_authentication_client(client: schemas.Client) -> schemas.Client:
    return client


@pytest.fixture
def secret_authenticated_client(client: schemas.Client) -> schemas.Client:
    client.authn_method = constants.ClientAuthnMethod.CLIENT_SECRET_POST
    client.hashed_secret = HASHED_CLIENT_SECRET
    return client


@pytest.fixture
def client_credentials_grant_context(secret_authenticated_client: schemas.Client) -> schemas.GrantContext:
    return schemas.GrantContext(
        grant_type=constants.GrantType.CLIENT_CREDENTIALS,
        client=secret_authenticated_client,
        token_model=secret_authenticated_client.token_model,
        requested_scopes=secret_authenticated_client.scopes,
        redirect_uri=None,
        refresh_token=None,
        authz_code=None,
        code_verifier=None,
        correlation_id=None
    )


@pytest.fixture
def authentication_session() -> schemas.AuthnSession:
    return schemas.AuthnSession(
        callback_id=CALLBACK_ID,
        tracking_id="",
        correlation_id="",
        client_id=CLIENT_ID,
        redirect_uri=REDIRECT_URI,
        requested_scopes=SCOPES,
        state=STATE,
        auth_policy_id=AUTHENTICATION_POLICY_ID,
        next_authn_step_id="",
        user_id=USER_ID,
        authz_code=AUTHORIZATION_CODE,
        authz_code_creation_timestamp=timestamp_now,
        code_challenge=None,
    )


@pytest.fixture
def authorization_code_grant_context(secret_authenticated_client: schemas.Client) -> schemas.GrantContext:
    return schemas.GrantContext(
        grant_type=constants.GrantType.AUTHORIZATION_CODE,
        client=secret_authenticated_client,
        token_model=secret_authenticated_client.token_model,
        requested_scopes=secret_authenticated_client.scopes,
        redirect_uri=REDIRECT_URI,
        refresh_token=None,
        authz_code=AUTHORIZATION_CODE,
        code_verifier=None,
        correlation_id=None
    )


@pytest.fixture
def autentication_policy() -> schemas.AuthnPolicy:
    return schemas.AuthnPolicy(
        id=AUTHENTICATION_POLICY_ID,
        is_available=lambda client, request: True,
        first_step=schemas.AuthnStep(
            id="first_step",
            authn_func=lambda session, request: schemas.AuthnStepSuccessResult(),
            success_next_step=None,
            failure_next_step=None
        ),
        get_extra_token_claims=None
    )


@pytest.fixture
def client_in() -> schemas.ClientIn:
    return schemas.ClientIn(
        id=CLIENT_ID,
        authn_method=constants.ClientAuthnMethod.CLIENT_SECRET_POST,
        redirect_uris=[REDIRECT_URI],
        response_types=[constants.ResponseType.CODE],
        grant_types=[constants.GrantType.AUTHORIZATION_CODE],
        scopes=SCOPES,
        token_model_id=TOKEN_MODEL_ID,
        is_pkce_required=True,
    )

######################################## Helper Test Functions ########################################


T = TypeVar("T")


async def async_return(o: T) -> T:
    return o
