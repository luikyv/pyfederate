import typing
from fastapi import APIRouter, status, Query, Response, Header, Depends

from ..utils.constants import GrantType
from ..utils import constants, telemetry, schemas
from ..utils import helpers

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
    response: Response,
    client: typing.Annotated[schemas.Client, Depends(helpers.get_authenticated_client)],
    grant_type: typing.Annotated[GrantType, Query()],
    code: typing.Annotated[str | None, Query()] = None,
    scope: typing.Annotated[str | None, Query()] = None,
    x_flow_id: typing.Annotated[str | None, Header(alias="X-Flow-ID")] = None,
):
    logger.info(f"Client {client.id} started the grant {grant_type.value}")
    requested_scopes: typing.List[str] = scope.split(" ")  if scope is not None else []

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

@router.get(
    "/authorize",
    status_code=status.HTTP_303_SEE_OTHER
)
async def authorize(
    client: typing.Annotated[schemas.Client, Depends(helpers.get_client)],
    response_type: constants.ResponseType
) -> None:
    return None