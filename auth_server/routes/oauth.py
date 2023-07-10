from typing import Optional, List
from fastapi import APIRouter, status, Query

from ..utils.constants import GrantType, TokenType
from ..utils.schemas import Client, TokenResponse
from ..utils import constants, exceptions
from ..auth_manager import manager as auth_manager

router = APIRouter(
    tags = ["oauth"]
)

@router.post(
    "/token",
    response_model=TokenResponse,
    response_model_exclude_none=True,
    status_code=status.HTTP_200_OK
)
async def token(
    client_id: str = Query(max_length=constants.CLIENT_ID_LENGH, min_length=constants.CLIENT_ID_LENGH),
    client_secret: str = Query(max_length=constants.CLIENT_SECRET_LENGH, min_length=constants.CLIENT_SECRET_LENGH),
    grant_type: GrantType = Query(),
    scope: Optional[str] = Query(default=None),
):
    
    client: Client = await auth_manager.client_manager.get_client(client_id=client_id)
    if(not client.is_authenticated(client_secret=client_secret)):
        raise exceptions.HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            error_code=constants.ErrorCode.ACCESS_DENIED,
            detail="invalid credentials"
        )
    
    # Check if the scopes requested are available to the client
    scopes: List[str] = scope.split(" ") if scope is not None else []
    if(not client.are_scopes_allowed(scopes=scopes)):
        raise exceptions.HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            error_code=constants.ErrorCode.ACCESS_DENIED,
            detail="the client does not have access to the required scopes"
        )

    if(grant_type == GrantType.CLIENT_CREDENTIALS):
        return TokenResponse(
            access_token="",
            token_type=TokenType.BEARER,
            expires_in=300
        )
    else:
        raise exceptions.HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            error_code=constants.ErrorCode.ACCESS_DENIED,
            detail="Problem"
        )

