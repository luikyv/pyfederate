from typing import Annotated, Awaitable, Callable, Dict, List
from fastapi import Form, Query, Path, Request, Response
import inspect

from ..utils import constants, telemetry, schemas, tools, exceptions
from .constants import GrantType, AuthnStatus
from ..auth_manager import manager

logger = telemetry.get_logger(__name__)

######################################## Dependency Functions ########################################


async def get_authenticated_client(
    client_id: Annotated[str, Form()],
    client_secret: Annotated[
        str | None,
        Form(
            min_length=constants.CLIENT_SECRET_MIN_LENGH,
            max_length=constants.CLIENT_SECRET_MAX_LENGH,
        ),
    ] = None,
) -> schemas.Client:

    try:
        client: schemas.Client = await manager.client_manager.get_client(
            client_id=client_id
        )
    except exceptions.EntityDoesNotExistException:
        raise exceptions.JsonResponseException(
            error=constants.ErrorCode.INVALID_REQUEST,
            error_description=f"client with id: {client_id} does not exist",
        )

    if client.authn_method == constants.ClientAuthnMethod.CLIENT_SECRET_POST:
        if client_secret is None or not client.is_authenticated_by_secret(
            client_secret=client_secret
        ):
            raise exceptions.JsonResponseException(
                error=constants.ErrorCode.INVALID_CLIENT,
                error_description=f"invalid credentials",
            )

    return client


async def get_client_as_form(client_id: Annotated[str, Form()]) -> schemas.Client:

    try:
        return await manager.client_manager.get_client(client_id=client_id)
    except exceptions.EntityDoesNotExistException:
        raise exceptions.JsonResponseException(
            error=constants.ErrorCode.INVALID_REQUEST,
            error_description=f"client with id: {client_id} does not exist",
        )


async def get_client_as_query(client_id: Annotated[str, Query()]) -> schemas.Client:

    try:
        return await manager.client_manager.get_client(client_id=client_id)
    except exceptions.EntityDoesNotExistException:
        raise exceptions.JsonResponseException(
            error=constants.ErrorCode.INVALID_REQUEST,
            error_description=f"client with id: {client_id} does not exist",
        )


def setup_telemetry(session: schemas.AuthnSession) -> None:
    """Overwrite the telemetry IDs set by default with the ones from the session"""

    telemetry.tracking_id.set(session.tracking_id)
    telemetry.correlation_id.set(session.correlation_id)


async def setup_session_by_callback_id(
    callback_id: Annotated[
        str,
        Path(
            min_length=constants.CALLBACK_ID_LENGTH,
            max_length=constants.CALLBACK_ID_LENGTH,
            description="ID generated during the /authorize",
        ),
    ]
) -> schemas.AuthnSession:
    """
    Fetch the session associated to the callback_id if it exists and
    set the tracking and correlation IDs using the session information
    """

    try:
        session: schemas.AuthnSession = (
            await manager.session_manager.get_session_by_callback_id(
                callback_id=callback_id
            )
        )
    except exceptions.EntityDoesNotExistException:
        raise exceptions.JsonResponseException(
            error=constants.ErrorCode.INVALID_REQUEST,
            error_description="invalid callback id",
        )
    setup_telemetry(session=session)
    return session


def get_scopes(scope_string: str | None) -> List[str]:
    if scope_string is None or scope_string == "":
        return []
    return scope_string.split(" ")


def get_scopes_as_form(
    scope: Annotated[
        str | None, Form(description="Space separeted list of scopes")
    ] = None
) -> List[str]:
    return get_scopes(scope_string=scope)


def get_scopes_required_as_form(
    scope: Annotated[str, Form(description="Space separeted list of scopes")]
) -> List[str]:
    return get_scopes(scope_string=scope)


def get_scopes_as_query(
    scope: Annotated[
        str | None, Query(description="Space separeted list of scopes")
    ] = None,
) -> List[str]:
    return get_scopes(scope_string=scope)


def get_response_types(response_type: str | None) -> List[constants.ResponseType]:
    if response_type is None or response_type == "":
        return []
    return [constants.ResponseType(rt) for rt in response_type.split(" ")]


def get_response_types_as_form(
    response_type: Annotated[str, Form()]
) -> List[constants.ResponseType]:
    return get_response_types(response_type=response_type)


def get_response_types_as_query(
    response_type: Annotated[str | None, Query()] = None
) -> List[constants.ResponseType]:
    return get_response_types(response_type=response_type)


######################################## /token ########################################

#################### Client Credentials ####################


def validate_client_credentials_grant(grant_context: schemas.GrantContext) -> None:

    if not grant_context.client.is_grant_type_allowed(
        grant_type=constants.GrantType.CLIENT_CREDENTIALS
    ):
        raise exceptions.JsonResponseException(
            error=constants.ErrorCode.INVALID_REQUEST,
            error_description=f"grant type not allowed",
        )

    if not grant_context.client.are_scopes_allowed(
        requested_scopes=grant_context.requested_scopes
    ):
        raise exceptions.JsonResponseException(
            error=constants.ErrorCode.INVALID_SCOPE,
            error_description=f"scope not allowed",
        )

    if (
        grant_context.redirect_uri
        or grant_context.authz_code
        or grant_context.code_verifier
        or grant_context.refresh_token
    ):
        raise exceptions.JsonResponseException(
            error=constants.ErrorCode.INVALID_REQUEST,
            error_description=f"invalid parameter",
        )


async def client_credentials_token_handler(
    grant_context: schemas.GrantContext,
) -> schemas.TokenResponse:

    validate_client_credentials_grant(grant_context=grant_context)

    timestamp_now = tools.get_timestamp_now()
    token_info = schemas.TokenInfo(
        subject=grant_context.client.id,
        issuer=grant_context.token_model.id,
        issued_at=timestamp_now,
        expiration=timestamp_now + grant_context.token_model.expires_in,
        client_id=grant_context.client.id,
        scopes=grant_context.requested_scopes,
        additional_info={},
    )
    return schemas.TokenResponse(
        access_token=grant_context.token_model.generate_token(token_info=token_info),
        expires_in=grant_context.token_model.expires_in,
    )


#################### Authorization Code ####################


async def setup_session_by_authz_code(authz_code: str) -> schemas.AuthnSession:
    """
    Fetch the session associated to the authorization code if it exists and
    set the tracking and correlation IDs using the session information
    """

    try:
        session: schemas.AuthnSession = (
            await manager.session_manager.get_session_by_authz_code(
                authz_code=authz_code
            )
        )
    except exceptions.EntityDoesNotExistException:
        raise exceptions.JsonResponseException(
            error=constants.ErrorCode.INVALID_GRANT, error_description=f"invalid code"
        )

    setup_telemetry(session=session)
    return session


async def create_token_session(
    authz_code_context: schemas.GrantContext, token_info: schemas.TokenInfo
) -> schemas.TokenSession:

    token_session = schemas.TokenSession(
        token_id=token_info.id,
        refresh_token=tools.generate_refresh_token()
        if (
            authz_code_context.client.is_grant_type_allowed(
                grant_type=constants.GrantType.REFRESH_TOKEN
            )
            and authz_code_context.token_model.is_refreshable
        )
        else None,
        client_id=authz_code_context.client.id,
        token_model_id=authz_code_context.token_model.id,
        token_info=token_info,
    )
    await manager.session_manager.create_token_session(session=token_session)
    return token_session


async def validate_authorization_code_grant(
    grant_context: schemas.GrantContext, session: schemas.AuthnSession
) -> None:

    if not grant_context.client.is_grant_type_allowed(
        grant_type=constants.GrantType.AUTHORIZATION_CODE
    ):
        raise exceptions.JsonResponseException(
            error=constants.ErrorCode.INVALID_REQUEST,
            error_description=f"grant type not allowed",
        )

    authz_code_creation: int = (
        session.authz_code_creation_timestamp
        if session.authz_code_creation_timestamp
        else 0
    )
    if grant_context.authz_code is None or (
        tools.get_timestamp_now()
        >= authz_code_creation + constants.AUTHORIZATION_CODE_TIMEOUT
    ):
        raise exceptions.JsonResponseException(
            error=constants.ErrorCode.INVALID_GRANT,
            error_description=f"the code expired",
        )

    if grant_context.client.id != session.client_id:
        await manager.session_manager.delete_session(session_id=session.id)
        raise exceptions.JsonResponseException(
            error=constants.ErrorCode.INVALID_REQUEST,
            error_description=f"code issued for another client",
        )

    if grant_context.redirect_uri != session.redirect_uri:
        raise exceptions.JsonResponseException(
            error=constants.ErrorCode.INVALID_REQUEST,
            error_description=f"invalid request_uri",
        )

    if grant_context.client.is_pkce_required and session.code_challenge is None:
        raise exceptions.JsonResponseException(
            error=constants.ErrorCode.ACCESS_DENIED, error_description=f"invalid pkce"
        )

    if session.code_challenge:
        # Raise exception when code verifier is not provided or it doesn't match the code challenge
        if grant_context.code_verifier is None or not tools.is_pkce_valid(
            code_verifier=grant_context.code_verifier,
            code_challenge=session.code_challenge,
        ):
            raise exceptions.JsonResponseException(
                error=constants.ErrorCode.ACCESS_DENIED,
                error_description=f"invalid pkce",
            )


async def authorization_code_token_handler(
    grant_context: schemas.GrantContext,
) -> schemas.TokenResponse:

    if grant_context.authz_code is None:
        raise exceptions.JsonResponseException(
            error=constants.ErrorCode.INVALID_GRANT, error_description=f"invalid code"
        )

    session: schemas.AuthnSession = await setup_session_by_authz_code(
        authz_code=grant_context.authz_code
    )
    await validate_authorization_code_grant(
        grant_context=grant_context, session=session
    )
    # Delete the session from storage to make sure the authz code can no longer be used
    await manager.session_manager.delete_session(session_id=session.id)

    # Generate the token
    authn_policy: schemas.AuthnPolicy = schemas.AUTHN_POLICIES[session.auth_policy_id]
    timestamp_now = tools.get_timestamp_now()
    token_info = schemas.TokenInfo(
        # The user_id was already validated by the validators in AuthorizationCodeContext
        subject=session.user_id,  # type: ignore
        issuer=grant_context.token_model.issuer,
        issued_at=timestamp_now,
        expiration=timestamp_now + grant_context.token_model.expires_in,
        client_id=grant_context.client.id,
        scopes=session.requested_scopes,
        additional_info=authn_policy.get_extra_token_claims(session)
        if authn_policy.get_extra_token_claims
        else {},
    )
    token_session: schemas.TokenSession = await create_token_session(
        authz_code_context=grant_context, token_info=token_info
    )
    return schemas.TokenResponse(
        access_token=grant_context.token_model.generate_token(token_info=token_info),
        refresh_token=token_session.refresh_token,
        expires_in=grant_context.token_model.expires_in,
    )


#################### Refresh Token ####################


def validate_refresh_token_grant(
    grant_context: schemas.GrantContext,
) -> None:
    if not grant_context.client.is_grant_type_allowed(
        grant_type=constants.GrantType.REFRESH_TOKEN
    ):
        raise exceptions.JsonResponseException(
            error=constants.ErrorCode.INVALID_REQUEST,
            error_description=f"grant type not allowed",
        )


async def update_token_session(
    token_session: schemas.TokenSession, token_model: schemas.TokenModel
) -> None:
    """Update the token session properties"""

    timestamp_now = tools.get_timestamp_now()
    # Update the token session
    token_session.token_info.expiration = timestamp_now
    token_session.token_info.expiration = timestamp_now + token_model.expires_in
    token_session.refresh_token = tools.generate_refresh_token()
    await manager.session_manager.update_token_session(session=token_session)


async def refresh_token_handler(
    grant_context: schemas.GrantContext,
) -> schemas.TokenResponse:

    validate_refresh_token_grant(grant_context=grant_context)
    if grant_context.refresh_token is None:
        raise exceptions.JsonResponseException(
            error=constants.ErrorCode.INVALID_GRANT,
            error_description=f"invalid refresh token",
        )

    try:
        token_session: schemas.TokenSession = (
            await manager.session_manager.get_token_session_by_refresh_token(
                refresh_token=grant_context.refresh_token
            )
        )
    except exceptions.EntityDoesNotExistException:
        raise exceptions.JsonResponseException(
            error=constants.ErrorCode.INVALID_GRANT,
            error_description=f"invalid refresh token",
        )

    token_model: schemas.TokenModel = await manager.token_model_manager.get_token_model(
        token_model_id=token_session.token_model_id
    )
    await update_token_session(token_session=token_session, token_model=token_model)
    return schemas.TokenResponse(
        access_token=token_model.generate_token(
            token_info=token_session.token_info,
        ),
        refresh_token=token_session.refresh_token,
        expires_in=token_model.expires_in,
    )


#################### Handler Object ####################

grant_handlers: Dict[
    GrantType, Callable[[schemas.GrantContext], Awaitable[schemas.TokenResponse]]
] = {
    GrantType.CLIENT_CREDENTIALS: client_credentials_token_handler,
    GrantType.AUTHORIZATION_CODE: authorization_code_token_handler,
    GrantType.REFRESH_TOKEN: refresh_token_handler,
}

######################################## /authorize ########################################


def validate_authorization_request(
    client: schemas.Client, authorize_session: schemas.AuthnSession
) -> None:
    if not client.are_scopes_allowed(
        requested_scopes=authorize_session.requested_scopes
    ):
        raise exceptions.JsonResponseException(
            error=constants.ErrorCode.INVALID_SCOPE,
            error_description="scope not allowed",
        )

    if not client.are_response_types_allowed(
        response_types=authorize_session.response_types
    ):
        raise exceptions.JsonResponseException(
            error=constants.ErrorCode.INVALID_REQUEST,
            error_description="response type not allowed",
        )

    if client.is_pkce_required and authorize_session.code_challenge is None:
        raise exceptions.JsonResponseException(
            error=constants.ErrorCode.INVALID_REQUEST,
            error_description="pkce is required",
        )


# def validate_authorization_request(authorize_context: schemas.AuthorizeContext) -> None:
#     if not authorize_context.client.are_scopes_allowed(
#         requested_scopes=authorize_context.requested_scopes
#     ):
#         raise exceptions.RedirectResponseException(
#             error=constants.ErrorCode.INVALID_SCOPE,
#             error_description="scope not allowed",
#             redirect_uri=authorize_context.redirect_uri,
#         )

#     if not authorize_context.client.are_response_types_allowed(
#         response_types=authorize_context.response_types
#     ):
#         raise exceptions.RedirectResponseException(
#             error=constants.ErrorCode.INVALID_REQUEST,
#             error_description="response type not allowed",
#             redirect_uri=authorize_context.redirect_uri,
#         )

#     if (
#         authorize_context.client.is_pkce_required
#         and authorize_context.code_challenge is None
#     ):
#         raise exceptions.RedirectResponseException(
#             error=constants.ErrorCode.INVALID_REQUEST,
#             error_description="pkce is required",
#             redirect_uri=authorize_context.redirect_uri,
#         )


######################################## Authn Status Handlers ########################################

#################### In Progress ####################


async def get_in_progress_next_step(
    session: schemas.AuthnSession,
    current_step: schemas.AuthnStep,
) -> schemas.AuthnStep | None:
    """Get the next step after reaching an in progress one"""

    # Update the session to indicate the processing stopped at the current step
    session.next_authn_step_id = current_step.id
    await manager.session_manager.update_session(session=session)


#################### Failure ####################


async def get_failure_next_step(
    session: schemas.AuthnSession,
    current_step: schemas.AuthnStep,
) -> schemas.AuthnStep | None:
    """Get the next step after reaching a failure one"""

    next_step = current_step.failure_next_step
    if next_step:
        return next_step

    # If the next step for a failure case is None, the policy failed,
    # then erase the session
    await manager.session_manager.delete_session(session_id=session.id)


#################### Success ####################


async def get_success_next_step(
    session: schemas.AuthnSession,
    current_step: schemas.AuthnStep,
) -> schemas.AuthnStep | None:
    """Get the next step after reaching a successful one"""

    next_step = current_step.success_next_step
    if next_step:
        return next_step

    # When the next step for a success case is None, the policy finished
    if session.user_id is None:
        # A policy ending in success must have an user_id mapped in the session
        return schemas.default_failure_step
    session.authz_code = tools.generate_authz_code()
    # After issuing the authz code, make sure the callback can't be called again
    session.callback_id = None
    session.authz_code_creation_timestamp = tools.get_timestamp_now()
    # Since the policy finished successfully, make sure it cannot be called again
    session.next_authn_step_id = schemas.default_failure_step.id
    await manager.session_manager.update_session(session=session)


#################### Handler Object ####################

# Map each status to a function that gets the next appropriate step
step_update_handler: Dict[
    AuthnStatus,
    Callable[
        [schemas.AuthnSession, schemas.AuthnStep],
        # Return the next step. Returning None means the partial processing of the policy finished
        Awaitable[schemas.AuthnStep | None],
    ],
] = {
    AuthnStatus.IN_PROGRESS: get_in_progress_next_step,
    AuthnStatus.FAILURE: get_failure_next_step,
    AuthnStatus.SUCCESS: get_success_next_step,
}


async def manage_authentication(
    session: schemas.AuthnSession,
    request: Request,
) -> Response:
    """Go through the available policy steps untill reach an end"""

    next_step: schemas.AuthnStep | None = schemas.AUTHN_STEPS.get(
        session.next_authn_step_id, schemas.default_failure_step
    )
    # It will be overwritten in the first iteration
    authn_result = schemas.AuthnStepFailureResult(error_description="server error")
    # Once the next step is None, the processing finished
    while next_step:
        authn_result_ = next_step.authn_func(session, request)
        authn_result: schemas.AuthnStepResult = (
            await authn_result_ if inspect.isawaitable(authn_result_) else authn_result_
        )  # type: ignore
        next_step = await step_update_handler[authn_result.status](session, next_step)

    # Return the response of the result generated in the last step of the loop
    return authn_result.get_response(session=session)
