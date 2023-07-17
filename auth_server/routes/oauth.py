from typing import Annotated, List
from fastapi import APIRouter, status, Query, Depends, Request, Response

from ..auth_manager import manager as auth_manager
from ..utils.constants import GrantType
from ..utils import constants, telemetry, schemas, tools, helpers, exceptions

logger = telemetry.get_logger(__name__)

router = APIRouter(
    tags=["oauth"]
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
    code: Annotated[str | None, Query()],
    scope: Annotated[str | None, Query()],
    redirect_uri: Annotated[str | None, Query()],
    code_verifier: Annotated[str | None, Query(min_length=43, max_length=128)],
    _: constants.CORRELATION_ID_HEADER_TYPE,
):
    logger.info(f"Client {client.id} started the grant {grant_type.value}")
    requested_scopes: List[str] = scope.split(" ") if scope is not None else []

    grant_context = schemas.GrantContext(
        client=client,
        token_model=client.token_model,
        requested_scopes=requested_scopes,
        redirect_uri=redirect_uri,
        authz_code=code,
        code_verifier=code_verifier
    )

    return await helpers.grant_handlers[grant_type](
        grant_context
    )


@router.get(
    "/authorize",
    status_code=status.HTTP_200_OK
)
async def authorize(
    request: Request,
    client: Annotated[schemas.Client, Depends(helpers.get_valid_client)],
    # The redirect_uri and scope params are already validated when building the client above
    redirect_uri: Annotated[str, Query()],
    scope: Annotated[str, Query()],
    state: Annotated[str, Query(max_length=constants.STATE_PARAM_MAX_LENGTH)],
    code_challenge: Annotated[str | None, Query()],
    code_challenge_method: Annotated[
        constants.CodeChallengeMethod,
        Query()
    ] = constants.CodeChallengeMethod.S256,
    _: constants.CORRELATION_ID_HEADER_TYPE = None,
) -> Response:

    try:
        authn_policy: schemas.AuthnPolicy = auth_manager.pick_policy(
            client=client, request=request)
        logger.info(f"Policy retrieved")
    except exceptions.NoAuthenticationPoliciesAvailable:
        logger.error(
            f"No authentication policy found for client with ID: {client.id}")
        raise exceptions.HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            error=constants.ErrorCode.INVALID_REQUEST,
            error_description="no policy found"
        )

    session = schemas.AuthnSession(
        id=tools.generate_session_id(),
        tracking_id=telemetry.tracking_id.get(),
        correlation_id=telemetry.correlation_id.get(),
        callback_id=tools.generate_callback_id(),
        user_id=None,
        client_id=client.id,
        redirect_uri=redirect_uri,
        state=state,
        auth_policy_id=authn_policy.id,
        next_authn_step_id=authn_policy.first_step.id,
        requested_scopes=scope.split(" "),
        authz_code=None,
        code_challenge=code_challenge
    )
    await auth_manager.session_manager.create_session(session=session)

    return await helpers.manage_authentication(session, request)


@router.post(
    "/authorize/{callback_id}",
    status_code=status.HTTP_200_OK
)
async def callback_authorize(
    session: Annotated[schemas.AuthnSession, Depends(helpers.setup_session_by_callback_id)],
    request: Request,
    _: constants.CORRELATION_ID_HEADER_TYPE = None,
):
    return await helpers.manage_authentication(session, request)
