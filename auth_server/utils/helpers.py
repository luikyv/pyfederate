from typing import Annotated, Awaitable, Callable, Dict
from fastapi import status, Query, Path, Request, Response
import inspect

from ..utils import constants, telemetry, schemas, tools, exceptions
from .constants import GrantType, AuthnStatus, ErrorCode
from ..auth_manager import manager as auth_manager

logger = telemetry.get_logger(__name__)

######################################## Dependency Functions ########################################

async def get_client(
        client_id: Annotated[
            str,
            Query(min_length=constants.CLIENT_ID_MIN_LENGH, max_length=constants.CLIENT_ID_MAX_LENGH)
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
            Query(min_length=constants.CLIENT_ID_MIN_LENGH, max_length=constants.CLIENT_ID_MAX_LENGH)
        ],
        response_type: Annotated[constants.ResponseType, Query()],
        redirect_uri: Annotated[str, Query()],
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
    
    if(not client.owns_redirect_uri(redirect_uri=redirect_uri)):
        logger.info(f"The client with ID: {client.id} doesn't own the redict_uri: {redirect_uri}")
        raise exceptions.HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            error=constants.ErrorCode.INVALID_REQUEST,
            error_description="invalid redirect_uri"
        )
    if(not client.is_response_type_allowed(response_type=response_type)):
        logger.info(f"The response type: {response_type} is not available to the client with ID: {client.id}")
        raise exceptions.HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            error=constants.ErrorCode.INVALID_REQUEST,
            error_description="invalid redirect_uri"
        )
    
    return client

async def get_authenticated_client(
        client_id: Annotated[
            str,
            Query(min_length=constants.CLIENT_ID_MIN_LENGH, max_length=constants.CLIENT_ID_MAX_LENGH)
        ],
        client_secret: Annotated[
            str,
            Query(min_length=constants.CLIENT_SECRET_MIN_LENGH, max_length=constants.CLIENT_SECRET_MAX_LENGH)
        ]
) -> schemas.Client:
    """Get client and verify that its secret matches client_secret"""
    
    client: schemas.Client = await get_client(client_id=client_id)

    if(not client.is_authenticated(client_secret=client_secret)):
        logger.info(f"The client with ID: {client_id} is not authenticated")
        raise exceptions.HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            error=constants.ErrorCode.INVALID_CLIENT,
            error_description="invalid credentials"
        )
    
    return client

async def setup_session_by_callback_id(
    callback_id: Annotated[str, Path(min_length=constants.CALLBACK_ID_LENGTH, max_length=constants.CALLBACK_ID_LENGTH)]
) -> schemas.SessionInfo:
    """
    Fetch the session associated to the callback_id if it exists and
    set the tracking and correlation IDs using the session information
    """
    
    try:
        session: schemas.SessionInfo = await auth_manager.session_manager.get_session_by_callback_id(callback_id=callback_id)
    except exceptions.SessionInfoDoesNotExist:
        logger.info(f"The callback ID: {callback_id} has no session associated with it")
        raise exceptions.HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            error=constants.ErrorCode.INVALID_REQUEST,
            error_description="Invalid callback ID"
        )
    
    # Overwrite the telemetry IDs set by default with the ones from the session
    telemetry.tracking_id.set(session.tracking_id)
    telemetry.correlation_id.set(session.correlation_id)
    return session

######################################## Grant Handlers ########################################

#################### Client Credentials ####################

async def client_credentials_token_handler(
    grant_context: schemas.GrantContext
) -> schemas.TokenResponse:
    
    client: schemas.Client = grant_context.client
    # Check if the scopes requested are available to the client
    if(not client.are_scopes_allowed(requested_scopes=grant_context.requested_scopes)):
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
        scopes=grant_context.requested_scopes if grant_context.requested_scopes else client.scopes
    )
    return schemas.TokenResponse(
        access_token=token.token,
        expires_in=token_model.expires_in
    )

#################### Authorization Code ####################

async def authorization_code_token_handler(
    grant_context: schemas.GrantContext
) -> schemas.TokenResponse:
    
    if(grant_context.authz_code is None):
        raise exceptions.HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            error=constants.ErrorCode.INVALID_GRANT,
            error_description="the authorization code cannot be null for the authorization_code grant"
        )

    session: schemas.SessionInfo = await auth_manager.session_manager.get_session_by_authz_code(
        authz_code=grant_context.authz_code
    )
    client: schemas.Client = grant_context.client

    # Ensure the client is the same one defined in the session
    if(client.id != session.client_id):
        raise exceptions.HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            error=constants.ErrorCode.INVALID_REQUEST,
            error_description="invalid authorization code"
        )
    # Check if the scopes requested are available to the client
    if(not client.are_scopes_allowed(requested_scopes=session.requested_scopes)):
        raise exceptions.HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            error=constants.ErrorCode.INVALID_SCOPE,
            error_description="the client does not have access to the required scopes"
        )

    token_model: schemas.TokenModel = client.token_model
    token: schemas.BearerToken = token_model.generate_token(
        client_id=client.id,
        subject=client.id,
        scopes=session.requested_scopes
    )
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
    session: schemas.SessionInfo,
    current_step: schemas.AuthnStep,
    step_result: schemas.AuthnStepResult
) -> schemas.AuthnStep | None:
    """Get the next step after reaching an in progress one"""
    
    # Update the session to indicate the processing
    # stopped at the current step
    session.current_authn_step_id = current_step.id

    # Since the current status is IN_PROGRESS,
    # return None to indicate the partial processing finished
    return None

#################### Failure ####################

async def get_failure_next_step(
    session: schemas.SessionInfo,
    current_step: schemas.AuthnStep,
    step_result: schemas.AuthnStepResult
) -> schemas.AuthnStep | None:
    """Get the next step after reaching a failure one"""
    
    if(not isinstance(step_result, schemas.AuthnStepFailureResult)):
        raise RuntimeError()

    next_step = current_step.failure_next_step
    # If the next step for a failure case is None, the policy failed
    if(next_step is None):
        step_result.set_redirect_uri(redirect_uri=session.redirect_uri)
        await auth_manager.session_manager.delete_session(tracking_id=session.tracking_id)

    return next_step

#################### Success ####################

async def get_success_next_step(
    session: schemas.SessionInfo,
    current_step: schemas.AuthnStep,
    step_result: schemas.AuthnStepResult
) -> schemas.AuthnStep | None:
    """Get the next step after reaching a successful one"""

    if(not isinstance(step_result, schemas.AuthnStepSuccessResult)):
        raise RuntimeError()
    
    next_step = current_step.success_next_step
    # If the next step for a success case is None, the policy finished successfully
    if(next_step is None):
        session.authz_code = tools.generate_authz_code()
        step_result.set_authz_code(session.authz_code)
        step_result.set_redirect_uri(redirect_uri=session.redirect_uri)
        step_result.set_state(state=session.state)

    return next_step

#################### Handler Object ####################

# Map each status to a function that gets the next appropriate step
step_update_handler: Dict[
    AuthnStatus,
    Callable[
        [schemas.SessionInfo, schemas.AuthnStep, schemas.AuthnStepResult],
        Awaitable[schemas.AuthnStep | None]
    ]
] = {
    AuthnStatus.IN_PROGRESS: get_in_progress_next_step,
    AuthnStatus.FAILURE: get_failure_next_step,
    AuthnStatus.SUCCESS: get_success_next_step
}

async def manage_authentication(
    session: schemas.SessionInfo,
    request: Request,
    response: Response
) -> Response:
    """Go through the available policy steps untill reach an end"""
    
    current_step: schemas.AuthnStep | None = schemas.AUTHN_STEPS.get(session.current_authn_step_id, schemas.default_failure_step)
    authn_result = None # type: ignore
    while(current_step):
        authn_result: schemas.AuthnStepResult = await current_step.authn_func(session, request)
        current_step = await step_update_handler[authn_result.status](
            session,
            current_step,
            authn_result
        )
    
    # Once the current step is None, the processing finished,
    # so we can return the updated response indicating success, failure, retry, etc.
    return authn_result.get_response()