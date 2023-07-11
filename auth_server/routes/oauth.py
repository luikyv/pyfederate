import typing
from fastapi import APIRouter, status, Query, Response

from . import helpers
from ..utils.constants import GrantType
from ..utils import schemas
from ..utils import constants
from ..auth_manager import manager as auth_manager

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
    client_id: str = Query(min_length=constants.CLIENT_ID_LENGH, max_length=constants.CLIENT_ID_LENGH),
    client_secret: str = Query(max_length=constants.CLIENT_SECRET_LENGH, min_length=constants.CLIENT_SECRET_LENGH),
    grant_type: GrantType = Query(),
    scope: typing.Optional[str] = Query(default=None),
):
    # Ensure clients don't cache the response
    response.headers["Cache-Control"] = "no-store"

    client: schemas.Client = await auth_manager.client_manager.get_client(client_id=client_id)
    requested_scopes: typing.List[str] = scope.split(" ")  if scope is not None else []

    helpers.validate_client(client=client, client_secret=client_secret, requested_scopes=requested_scopes)

    return helpers.grant_handlers[grant_type](
        client,
        requested_scopes,
    )