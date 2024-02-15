from typing import Annotated, Awaitable, Callable, Dict, List
from fastapi import Form, Query, Path
import base64
from hashlib import sha256

from ..utils.client import Client
from ..utils.token import TokenModel
from ..utils.tools import generate_fixed_size_random_string
from ..utils.exceptions import OAuthJsonResponseException, OAuthRedirectResponseException
from ..utils.constants import ErrorCode, GrantType, ResponseType
from ..utils.config import REQUEST_URI_LENGTH, SECRET_ENCODING, CALLBACK_ID_LENGTH
from ..crud.auth import AuthCRUDManager
from ..crud.exceptions import EntityDoesNotExistException
from ..schemas.client import ClientAuthnContext
from ..schemas.oauth import GrantContext, TokenResponse
from ..schemas.token import TokenContextInfo, Token
from ..schemas.auth import AuthnSession


def _get_scopes(scope_string: str | None) -> List[str]:
    return scope_string.split(" ") if scope_string is not None else []


def get_scopes_as_form(
    scope: Annotated[
        str | None, Form(description="Space separeted list of scopes")
    ] = None
) -> List[str]:
    return _get_scopes(scope_string=scope)


def get_scopes_as_query(
    scope: Annotated[
        str | None, Query(description="Space separeted list of scopes")
    ] = None,
) -> List[str]:
    return _get_scopes(scope_string=scope)


def get_response_types(response_type: str) -> List[ResponseType]:
    return [ResponseType(rt) for rt in response_type.split(" ")]


def get_response_types_as_form(
    response_type: Annotated[str, Form()]
) -> List[ResponseType]:
    return get_response_types(response_type=response_type)


def get_response_types_as_query(
    response_type: Annotated[str, Query()]
) -> List[ResponseType]:
    return get_response_types(response_type=response_type)


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


async def get_client_as_query(client_id: Annotated[str, Query()]) -> Client:

    client_manager = AuthCRUDManager.get_manager().client_manager
    try:
        return await client_manager.get_client(client_id=client_id)
    except EntityDoesNotExistException:
        raise OAuthJsonResponseException(
            error=ErrorCode.INVALID_REQUEST,
            error_description=f"client with id: {client_id} does not exist",
        )


async def get_session_by_callback_id(
    callback_id: Annotated[
        str,
        Path(
            min_length=CALLBACK_ID_LENGTH,
            max_length=CALLBACK_ID_LENGTH,
            description="ID generated during the /authorize",
        ),
    ]
) -> AuthnSession:
    """
    Fetch the session associated to the callback_id if it exists and
    set the tracking and correlation IDs using the session information
    """

    try:
        session: AuthnSession = await AuthCRUDManager.get_manager().authn_session_manager.get_session_by_callback_id(
            callback_id=callback_id
        )
    except EntityDoesNotExistException:
        raise OAuthJsonResponseException(
            error=ErrorCode.INVALID_REQUEST,
            error_description="invalid callback id",
        )
    return session


def generate_request_uri() -> str:
    return f"urn:ietf:params:oauth:request_uri:{generate_fixed_size_random_string(length=REQUEST_URI_LENGTH)}"


def pkce_is_valid(code_verifier: str, code_challenge: str) -> bool:
    hashed_code_verifier = (
        base64.urlsafe_b64encode(sha256(code_verifier.encode(SECRET_ENCODING)).digest())
        .decode(SECRET_ENCODING)
        .replace("=", "")
    )  # Remove padding '='
    return hashed_code_verifier == code_challenge


async def _get_token_model(
    token_model_id: str | None, default_token_model_id
) -> TokenModel:

    token_model_manager = AuthCRUDManager.get_manager().token_model_manager
    if token_model_id:
        return await token_model_manager.get_token_model(token_model_id=token_model_id)

    return await token_model_manager.get_token_model(
        token_model_id=default_token_model_id
    )


def _validate_client_credentials_grant(
    grant_context: GrantContext, client: Client
) -> None:
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


async def _client_credentials_grant_handler(
    grant_context: GrantContext, client: Client
) -> Token:
    _validate_client_credentials_grant(grant_context=grant_context, client=client)

    token_model: TokenModel = await _get_token_model(
        token_model_id=None, default_token_model_id=client.get_default_token_model_id()
    )
    return token_model.generate_token(
        context=TokenContextInfo(
            subject=client.get_id(),
            client_id=client.get_id(),
            scopes=grant_context.scopes
            if grant_context.scopes
            else client.get_available_scopes(),
        )
    )

def _validate_authorization_code_grant(
    grant_context: GrantContext, session: AuthnSession
) -> None:
    if grant_context.scopes:
        raise OAuthJsonResponseException(
            error=ErrorCode.INVALID_REQUEST, error_description="invalid request"
        )

    if session.redirect_uri != grant_context.redirect_uri:
        raise OAuthJsonResponseException(
            error=ErrorCode.INVALID_REQUEST, error_description="invalid redirect URI"
        )
    
    if (
        session.code_challenge
        and not grant_context.code_verifier
    ):
        raise OAuthJsonResponseException(
            error=ErrorCode.INVALID_REQUEST, error_description="invalid pkce"
        )

    if(
        session.code_challenge
        and not pkce_is_valid(
            code_verifier=grant_context.code_verifier,
            code_challenge=session.code_challenge
        )
    ):
        raise OAuthJsonResponseException(
            error=ErrorCode.INVALID_REQUEST, error_description="invalid pkce"
        )

async def _get_and_delete_valid_authentication_session(
    grant_context: GrantContext
) -> AuthnSession:
    
    if not grant_context.authz_code:
        raise OAuthJsonResponseException(
            error=ErrorCode.INVALID_REQUEST, error_description="invalid request"
        )
    
    session: AuthnSession = await AuthCRUDManager.get_manager().authn_session_manager.get_session_by_authz_code(
        authz_code=grant_context.authz_code
    )
    await AuthCRUDManager.get_manager().authn_session_manager.delete_session(session_id=session.id)
    return session

async def _authorization_code_grant_handler(
    grant_context: GrantContext, client: Client
) -> Token:
    
    session: AuthnSession = await _get_and_delete_valid_authentication_session(grant_context=grant_context)
    _validate_authorization_code_grant(
        grant_context=grant_context,
        session=session
    )

    token_model: TokenModel = await _get_token_model(
        token_model_id=None, default_token_model_id=client.get_default_token_model_id()
    )
    return token_model.generate_token(
        context=TokenContextInfo(
            subject=session.subject,
            client_id=client.get_id(),
            scopes=session.scopes,
        )
    )



grant_handlers: Dict[
    GrantType, Callable[[GrantContext, Client], Awaitable[Token]]
] = {
    GrantType.CLIENT_CREDENTIALS: _client_credentials_grant_handler,
    GrantType.AUTHORIZATION_CODE: _authorization_code_grant_handler,
}


def validate_authorization_request(client: Client, session: AuthnSession) -> None:
    
    if not client.owns_redirect_uri(redirect_uri=session.redirect_uri):
        raise OAuthJsonResponseException(
            error=ErrorCode.INVALID_REQUEST,
            error_description="invalid redirect_uri",
        )

    if not client.scopes_are_allowed(scopes=session.scopes):
        raise OAuthRedirectResponseException(
            error=ErrorCode.INVALID_SCOPE,
            error_description="scope not allowed",
            redirect_uri=session.redirect_uri,
            state=session.state
        )

    if not client.response_types_are_allowed(
        response_types=session.response_types
    ):
        raise OAuthRedirectResponseException(
            error=ErrorCode.INVALID_REQUEST,
            error_description="response type not allowed",
            redirect_uri=session.redirect_uri,
            state=session.state
        )

    if client.pkce_is_required() and not session.code_challenge:
        raise OAuthRedirectResponseException(
            error=ErrorCode.INVALID_REQUEST,
            error_description="pkce is required",
            redirect_uri=session.redirect_uri,
            state=session.state
        )

