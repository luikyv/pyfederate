from typing import Annotated, Awaitable, Callable, Dict, List
from fastapi import Form
import base64
from hashlib import sha256

from ..utils.client import Client
from ..utils.tools import generate_fixed_size_random_string
from ..utils.exceptions import OAuthJsonResponseException
from ..utils.constants import ErrorCode, GrantType
from ..utils.config import REQUEST_URI_LENGTH, SECRET_ENCODING
from ..crud.auth import AuthCRUDManager
from ..crud.exceptions import EntityDoesNotExistException
from ..schemas.client import ClientAuthnContext
from ..schemas.oauth import GrantContext, TokenResponse


def _get_scopes(scope_string: str | None) -> List[str] | None:
    return scope_string.split(" ") if scope_string is not None else None


def get_scopes_as_form(
    scope: Annotated[
        str | None, Form(description="Space separeted list of scopes")
    ] = None
) -> List[str] | None:
    return _get_scopes(scope_string=scope)


async def get_authenticated_client(
    client_id: Annotated[str, Form()],
    client_secret: Annotated[
        str | None,
        Form(),
    ] = None,
) -> Client:

    client_manager = AuthCRUDManager.get_manager().client_manager
    try:
        client: Client = await client_manager.get_client(client_id=client_id)
    except EntityDoesNotExistException as e:
        raise e

    client_authn_context = ClientAuthnContext(secret=client_secret)
    if not client.is_authenticated(authn_context=client_authn_context):
        raise OAuthJsonResponseException(
            error=ErrorCode.ACCESS_DENIED, error_description="access denied"
        )

    return client


def generate_request_uri() -> str:
    return f"urn:ietf:params:oauth:request_uri:{generate_fixed_size_random_string(length=REQUEST_URI_LENGTH)}"


def is_pkce_valid(code_verifier: str, code_challenge: str) -> bool:
    hashed_code_verifier = (
        base64.urlsafe_b64encode(sha256(code_verifier.encode(SECRET_ENCODING)).digest())
        .decode(SECRET_ENCODING)
        .replace("=", "")
    )  # Remove padding '='
    return hashed_code_verifier == code_challenge


async def client_credentials_token_handler(
    grant_context: GrantContext, client: Client
) -> TokenResponse:
    if any(
        [
            grant_context.authz_code,
            grant_context.code_verifier,
            grant_context.redirect_uri,
            grant_context.refresh_token,
        ]
    ):
        raise OAuthJsonResponseException(
            error=ErrorCode.INVALID_REQUEST, error_description="invalid request"
        )
    if grant_context.scopes and not client.are_scopes_allowed(
        scopes=grant_context.scopes
    ):
        raise OAuthJsonResponseException(
            error=ErrorCode.INVALID_REQUEST, error_description="invalid request"
        )

    scopes: List[str] = (
        grant_context.scopes if grant_context.scopes else client.get_available_scopes()
    )
    return TokenResponse()  # type: ignore


grant_handlers: Dict[
    GrantType, Callable[[GrantContext, Client], Awaitable[TokenResponse]]
] = {
    GrantType.CLIENT_CREDENTIALS: client_credentials_token_handler,
    # GrantType.AUTHORIZATION_CODE: authorization_code_token_handler,
    # GrantType.REFRESH_TOKEN: refresh_token_handler,
}
