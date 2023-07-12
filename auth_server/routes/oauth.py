import typing
from fastapi import APIRouter, status, Query, Response, Header

from ..utils.constants import GrantType
from ..utils import constants, telemetry, schemas
from . import helpers
from ..auth_manager import manager as auth_manager

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
async def token(
    response: Response,
    client_id: typing.Annotated[str, Query(min_length=constants.CLIENT_ID_LENGH, max_length=constants.CLIENT_ID_LENGH)],
    client_secret: typing.Annotated[str, Query(max_length=constants.CLIENT_SECRET_LENGH, min_length=constants.CLIENT_SECRET_LENGH)],
    grant_type: typing.Annotated[GrantType, Query()],
    code: typing.Annotated[str | None, Query()] = None,
    scope: typing.Annotated[str | None, Query()] = None,
    x_flow_id: typing.Annotated[str | None, Header(alias="X-Flow-ID")] = None,
):
    logger.info(f"Client {client_id} started the grant {grant_type.value}")
    requested_scopes: typing.List[str] = scope.split(" ")  if scope is not None else []
    client: schemas.Client = await helpers.get_valid_client(
        client_id=client_id,
        client_secret=client_secret,
        requested_scopes=requested_scopes
    )

    grant_context = schemas.GrantContext(
        client=client,
        token_model=client.token_model,
        requested_scopes=requested_scopes
    )
    # Ensure clients don't cache the response
    response.headers["Cache-Control"] = "no-store"

    return helpers.grant_handlers[grant_type](
        grant_context
    )