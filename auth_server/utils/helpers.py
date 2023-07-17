from typing import Annotated, Awaitable, Callable, Dict
from fastapi import status, Query, Path, Request, Response
import inspect

from ..utils import constants, telemetry, schemas, tools, exceptions
from .constants import GrantType, AuthnStatus
from ..auth_manager import manager as auth_manager

logger = telemetry.get_logger(__name__)

######################################## Dependency Functions ########################################


async def get_client(
        client_id: Annotated[
            str,
            Query(min_length=constants.CLIENT_ID_MIN_LENGH,
                  max_length=constants.CLIENT_ID_MAX_LENGH)
        ]
) -> schemas.Client:

    try:
        client: schemas.Client = await auth_manager.client_manager.get_client(client_id=client_id)
    except exceptions.ClientDoesNotExist:
        logger.info(f"The client with ID: {client_id} does not exists")
        raise exceptions.HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            error=constants.ErrorCode.INVALID_CLIENT,
            error_description="invalid credentials"
        )

    return client


async def get_valid_client(
        client_id: Annotated[
            str,
            Query(min_length=constants.CLIENT_ID_MIN_LENGH,
                  max_length=constants.CLIENT_ID_MAX_LENGH)
        ],
        scope: Annotated[str, Query()],
        response_type: Annotated[constants.ResponseType, Query()],
        redirect_uri: Annotated[str, Query()],
) -> schemas.Client:

    client: schemas.Client = await get_client(client_id=client_id)

    # Check if the scopes requested are available to the client
    if (not client.are_scopes_allowed(requested_scopes=scope.split(" "))):
        raise exceptions.HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            error=constants.ErrorCode.INVALID_SCOPE,
            error_description="the client does not have access to the required scopes"
        )
    # Check if the request_uri belongs to the client
    if (not client.owns_redirect_uri(redirect_uri=redirect_uri)):
        logger.info(
            f"The client with ID: {client.id} doesn't own the redict_uri: {redirect_uri}")
        raise exceptions.HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            error=constants.ErrorCode.INVALID_REQUEST,
            error_description="invalid redirect_uri"
        )
    # Check if the requested response type is allowed for the client
    if (not client.is_response_type_allowed(response_type=response_type)):
        logger.info(
            f"The response type: {response_type} is not available to the client with ID: {client.id}")
        raise exceptions.HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            error=constants.ErrorCode.INVALID_REQUEST,
            error_description="invalid redirect_uri"
        )

    return client


async def get_authenticated_client(
        client_id: Annotated[
            str,
            Query(min_length=constants.CLIENT_ID_MIN_LENGH,
                  max_length=constants.CLIENT_ID_MAX_LENGH)
        ],
        client_secret: Annotated[
            str,
            Query(min_length=constants.CLIENT_SECRET_MIN_LENGH,
                  max_length=constants.CLIENT_SECRET_MAX_LENGH)
        ]
) -> schemas.Client:
    """Get client and verify that its secret matches client_secret"""

    client: schemas.Client = await get_client(client_id=client_id)

    if (not client.is_authenticated(client_secret=client_secret)):
        logger.info(f"The client with ID: {client_id} is not authenticated")
        raise exceptions.HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            error=constants.ErrorCode.INVALID_CLIENT,
            error_description="invalid credentials"
        )

    return client


def setup_telemetry(
    session: schemas.AuthnSession
) -> None:
    # Overwrite the telemetry IDs set by default with the ones from the session
    telemetry.tracking_id.set(session.tracking_id)
    telemetry.correlation_id.set(session.correlation_id)


async def setup_session_by_callback_id(
    callback_id: Annotated[str, Path(
        min_length=constants.CALLBACK_ID_LENGTH, max_length=constants.CALLBACK_ID_LENGTH)]
) -> schemas.AuthnSession:
    """
    Fetch the session associated to the callback_id if it exists and
    set the tracking and correlation IDs using the session information
    """

    try:
        session: schemas.AuthnSession = await auth_manager.session_manager.get_session_by_callback_id(callback_id=callback_id)
    except exceptions.SessionInfoDoesNotExist:
        logger.info(
            f"The callback ID: {callback_id} has no session associated with it")
        raise exceptions.HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            error=constants.ErrorCode.INVALID_REQUEST,
            error_description="Invalid callback ID"
        )

    setup_telemetry(session=session)
    return session

######################################## Grant Handlers ########################################

#################### Client Credentials ####################


async def client_credentials_token_handler(
    grant_context: schemas.GrantContext
) -> schemas.TokenResponse:

    client: schemas.Client = grant_context.client
    # Check if the scopes requested are available to the client
    if (not client.are_scopes_allowed(requested_scopes=grant_context.requested_scopes)):
        raise exceptions.HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            error=constants.ErrorCode.INVALID_SCOPE,
            error_description="the client does not have access to the required scopes"
        )

    token_model: schemas.TokenModel = client.token_model
    token: schemas.BearerToken = token_model.generate_token(
        client_id=client.id,
        subject=client.id,
        # If the client didn't inform any scopes, send all the available ones
        scopes=grant_context.requested_scopes if grant_context.requested_scopes else client.scopes,
        additional_claims={}
    )
    return schemas.TokenResponse(
        access_token=token.token,
        expires_in=token_model.expires_in
    )

#################### Authorization Code ####################


async def setup_session_by_authz_code(
    authz_code: str
) -> schemas.AuthnSession:
    """
    Fetch the session associated to the authorization code if it exists and
    set the tracking and correlation IDs using the session information
    """

    try:
        session: schemas.AuthnSession = await auth_manager.session_manager.get_session_by_authz_code(authz_code=authz_code)
    except exceptions.SessionInfoDoesNotExist:
        logger.info(
            f"The authorization code: {authz_code} has no session associated with it"
        )
        raise exceptions.HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            error=constants.ErrorCode.INVALID_REQUEST,
            error_description="Invalid authorization code"
        )

    setup_telemetry(session=session)
    return session


async def get_valid_authorization_code_session(grant_context: schemas.GrantContext) -> schemas.AuthnSession:

    # Ensure the authz code exists
    if (grant_context.authz_code is None):
        raise exceptions.HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            error=constants.ErrorCode.INVALID_GRANT,
            error_description="the authorization code cannot be null for the authorization_code grant"
        )

    session: schemas.AuthnSession = await setup_session_by_authz_code(authz_code=grant_context.authz_code)

    # Ensure the client is the same one defined in the session
    if (grant_context.client.id != session.client_id):
        raise exceptions.HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            error=constants.ErrorCode.INVALID_REQUEST,
            error_description="invalid authorization code"
        )
    # Ensure the redirect uri passed during the /authorize step is the same passed in the /token
    if (grant_context.redirect_uri is None or grant_context.redirect_uri != session.redirect_uri):
        raise exceptions.HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            error=constants.ErrorCode.INVALID_REQUEST,
            error_description="invalid redirect uri"
        )
    # Ensure the user id is defined in the session
    if (session.user_id is None):
        raise exceptions.HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            error=constants.ErrorCode.ACCESS_DENIED,
            error_description="access denied"
        )

    return session


async def authorization_code_token_handler(
    grant_context: schemas.GrantContext
) -> schemas.TokenResponse:

    client: schemas.Client = grant_context.client
    token_model: schemas.TokenModel = grant_context.token_model
    session: schemas.AuthnSession = await get_valid_authorization_code_session(grant_context=grant_context)

    # Generate token
    authn_policy: schemas.AuthnPolicy = schemas.AUTHN_POLICIES[session.auth_policy_id]
    token: schemas.BearerToken = token_model.generate_token(
        client_id=client.id,
        subject=session.user_id,  # type: ignore
        scopes=session.requested_scopes,
        additional_claims=authn_policy.get_extra_token_claims(
            session) if authn_policy.get_extra_token_claims else {}
    )
    # Delete the session to make sure the authz code can no longer be used
    await auth_manager.session_manager.delete_session(session_id=session.id)
    return schemas.TokenResponse(
        access_token=token.token,
        expires_in=token_model.expires_in
    )

#################### Handler Object ####################

grant_handlers: Dict[
    GrantType,
    Callable[
        [schemas.GrantContext], Awaitable[schemas.TokenResponse]
    ]
] = {
    GrantType.CLIENT_CREDENTIALS: client_credentials_token_handler,
    GrantType.AUTHORIZATION_CODE: authorization_code_token_handler
}

######################################## Authn Status Handlers ########################################

#################### In Progress ####################


async def get_in_progress_next_step(
    session: schemas.AuthnSession,
    current_step: schemas.AuthnStep,
) -> schemas.AuthnStep | None:
    """Get the next step after reaching an in progress one"""

    # Update the session to indicate the processing stopped at the current step
    session.next_authn_step_id = current_step.id
    await auth_manager.session_manager.update_session(session=session)

#################### Failure ####################


async def get_failure_next_step(
    session: schemas.AuthnSession,
    current_step: schemas.AuthnStep,
) -> schemas.AuthnStep | None:
    """Get the next step after reaching a failure one"""

    next_step = current_step.failure_next_step
    if (next_step):
        return next_step

    # If the next step for a failure case is None, the policy failed,
    # then erase the session
    await auth_manager.session_manager.delete_session(session_id=session.id)

#################### Success ####################


async def get_success_next_step(
    session: schemas.AuthnSession,
    current_step: schemas.AuthnStep,
) -> schemas.AuthnStep | None:
    """Get the next step after reaching a successful one"""

    next_step = current_step.success_next_step
    if (next_step):
        return next_step

    # When the next step for a success case is None, the policy finished
    if (session.user_id is None):
        # A policy ending in success must have an user_id mapped in the session
        return schemas.default_failure_step
    session.authz_code = tools.generate_authz_code()
    # Since the policy finished successfully, make sure it cannot be called again
    session.next_authn_step_id = schemas.default_failure_step.id
    await auth_manager.session_manager.update_session(session=session)


#################### Handler Object ####################

# Map each status to a function that gets the next appropriate step
step_update_handler: Dict[
    AuthnStatus,
    Callable[
        [schemas.AuthnSession, schemas.AuthnStep],
        # Return the next step. Returning None means the partial processing of the policy finished
        Awaitable[schemas.AuthnStep | None]
    ]
] = {
    AuthnStatus.IN_PROGRESS: get_in_progress_next_step,
    AuthnStatus.FAILURE: get_failure_next_step,
    AuthnStatus.SUCCESS: get_success_next_step
}


async def manage_authentication(
    session: schemas.AuthnSession,
    request: Request,
) -> Response:
    """Go through the available policy steps untill reach an end"""

    next_step: schemas.AuthnStep | None = schemas.AUTHN_STEPS.get(
        session.next_authn_step_id, schemas.default_failure_step)
    # It will be overwritten in the first iteration
    authn_result = schemas.AuthnStepFailureResult(
        error_description="server error")
    # Once the next step is None, the processing finished
    while (next_step):
        authn_result_ = next_step.authn_func(session, request)
        authn_result: schemas.AuthnStepResult = (
            await authn_result_
            if inspect.isawaitable(authn_result_)
            else authn_result_
        )  # type: ignore
        next_step = await step_update_handler[authn_result.status](
            session,
            next_step
        )

    # Return the response of the result generated in the last step of the loop
    return authn_result.get_response(session=session)
