import typing
from fastapi import APIRouter, status, Query, Response

from ..utils.constants import GrantType
from ..utils import schemas
from ..utils import constants, exceptions
from ..auth_manager import manager as auth_manager

def validate_client(client: schemas.Client, client_secret: str, scopes: typing.List[str]) -> None:
    if(not client.is_authenticated(client_secret=client_secret)):
        raise exceptions.HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            error=constants.ErrorCode.ACCESS_DENIED,
            error_description="invalid credentials"
        )
    
    # Check if the scopes requested are available to the client
    if(not client.are_scopes_allowed(scopes=scopes)):
        raise exceptions.HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            error=constants.ErrorCode.ACCESS_DENIED,
            error_description="the client does not have access to the required scopes"
        )

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
    token_model: schemas.TokenModel = client.token_model
    requested_scopes: typing.List[str] = scope.split(" ")  if scope is not None else []

    validate_client(client=client, client_secret=client_secret, scopes=requested_scopes)

    if(grant_type == GrantType.CLIENT_CREDENTIALS):
        token: schemas.BearerToken = token_model.generate_token(
            client_id=client.id,
            subject=client.id,
            scopes=client.scopes if requested_scopes else requested_scopes
        )
        return schemas.TokenResponse(
            access_token=token.token,
            expires_in=token_model.expires_in
        )
    else:
        raise exceptions.HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            error=constants.ErrorCode.ACCESS_DENIED,
            error_description="Problem"
        )

