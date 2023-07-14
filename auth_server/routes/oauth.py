from typing import Annotated, List
from fastapi import APIRouter, status, Query, Path, Depends
from fastapi.responses import HTMLResponse, RedirectResponse

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
        auth_code=code
    )

    return await helpers.grant_handlers[grant_type](
        grant_context
    )

@router.get(
    "/authorize",
    response_class=HTMLResponse,
    status_code=status.HTTP_200_OK
)
async def authorize(
    client: Annotated[schemas.Client, Depends(helpers.get_client)],
    response_type: Annotated[constants.ResponseType, Path()],
    redirect_uri: Annotated[str, Path()],
    scope: Annotated[str, Path()],
    state: Annotated[str, Path(max_length=constants.STATE_PARAM_MAX_LENGTH)],
    _: constants.CORRELATION_ID_HEADER_TYPE = None,
) -> str:
    
    if(not client.owns_redirect_uri(redirect_uri=redirect_uri)):
        logger.info(f"The client with ID: {client.id} doesn't own the redict_uri: {redirect_uri}")
        raise exceptions.HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            error=constants.ErrorCode.INVALID_REQUEST,
            error_description="invalid redirect_uri"
        )
    
    callback_id: str = tools.generate_callback_id()
    await auth_manager.session_manager.create_session(
        schemas.SessionInfo(
            tracking_id=telemetry.tracking_id.get(),
            correlation_id=telemetry.correlation_id.get(),
            callback_id=callback_id,
            subject=None,
            client_id=client.id,
            redirect_uri=redirect_uri,
            state=state,
            requested_scopes=scope.split(" "),
            auth_code=None
        )
    )
    
    return f"""
            <form action="/authorize/{callback_id}" method="post">
            <input type="submit" value="Submit">
            </form>
        """

@router.post(
    "/authorize/{callback_id}",
)
async def callback_authorize(
    session: Annotated[schemas.SessionInfo, Depends(helpers.setup_session_by_callback_id)]
):
    session.auth_code = tools.generate_auth_code()
    return RedirectResponse(
        url=tools.prepare_url(session.redirect_uri, {
            "code": session.auth_code,
            "state": session.state,
        }),
        status_code=status.HTTP_303_SEE_OTHER
    )