from typing import Annotated, List
from fastapi import APIRouter, status, Query, Depends, Request, Response

from ..auth_manager import manager as auth_manager
from ..utils.constants import GrantType
from ..utils import constants, telemetry, schemas, tools, helpers, exceptions

logger = telemetry.get_logger(__name__)

router = APIRouter(
    tags = ["oauth"]
)

@router.post(
    "/token",
    response_model=schemas.TokenResponse,
    response_model_exclude_none=True,
    status_code=status.HTTP_200_OK
)
async def get_token(
    client: Annotated[schemas.Client, Depends(helpers.get_authenticated_client)],
    grant_type: Annotated[GrantType, Query()],
    code: Annotated[str | None, Query()] = None,
    scope: Annotated[str | None, Query()] = None,
    _: constants.CORRELATION_ID_HEADER_TYPE = None,
):
    logger.info(f"Client {client.id} started the grant {grant_type.value}")
    requested_scopes: List[str] = scope.split(" ")  if scope is not None else []

    grant_context = schemas.GrantContext(
        client=client,
        token_model=client.token_model,
        requested_scopes=requested_scopes,
        authz_code=code
    )

    return await helpers.grant_handlers[grant_type](
        grant_context
    )

@router.get(
    "/authorize",
    status_code=status.HTTP_200_OK
)
async def authorize(
    client: Annotated[schemas.Client, Depends(helpers.get_valid_client)],
    redirect_uri: Annotated[str, Query()], # This redirect_uri is already validated when creating the client
    scope: Annotated[str, Query()],
    state: Annotated[str, Query(max_length=constants.STATE_PARAM_MAX_LENGTH)],
    request: Request,
    response: Response,
    _: constants.CORRELATION_ID_HEADER_TYPE = None,
):
    
    try:
        authn_first_step: schemas.AuthnStep = auth_manager.pick_policy().first_step
        logger.info(f"Policy retrieved")
    except exceptions.NoAuthenticationPoliciesAvailable:
        logger.error(f"No authentication policy found for client with ID: {client.id}")
        raise exceptions.HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            error=constants.ErrorCode.INVALID_REQUEST,
            error_description="no policy found"
        )
    
    session = schemas.SessionInfo(
        tracking_id=telemetry.tracking_id.get(),
        correlation_id=telemetry.correlation_id.get(),
        callback_id=tools.generate_callback_id(),
        user_id=None,
        client_id=client.id,
        redirect_uri=redirect_uri,
        state=state,
        current_authn_step_id=authn_first_step.id,
        requested_scopes=scope.split(" "),
        authz_code=None
    )
    await auth_manager.session_manager.create_session(session_info=session)

    return await helpers.manage_authentication(session, request, response)


@router.post(
    "/authorize/{callback_id}",
    status_code=status.HTTP_200_OK
)
async def callback_authorize(
    session: Annotated[schemas.SessionInfo, Depends(helpers.setup_session_by_callback_id)],
    request: Request,
    response: Response,
):
    return await helpers.manage_authentication(session, request, response)