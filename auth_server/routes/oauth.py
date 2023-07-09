"""
OAuth 2 Endpoints
"""

from typing import Optional
from fastapi import APIRouter, status, HTTPException
from fastapi.responses import JSONResponse

from ..utils.constants import GrantType, TokenType, ErrorCode
from ..utils.schemas import Client, ErrorMessage, TokenResponse
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
    client_id: str,
    client_secret: str,
    grant_type: GrantType,
    scope: Optional[str] = None,
):
    
    client: Client = await auth_manager.client_manager.get_client(client_id=client_id)
    if(client.is_authenticated(client_secret=client_secret) is False):
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content=ErrorMessage(
                error_code=ErrorCode.ACCESS_DENIED,
                error_description="invalid credentials"
            ).dict()
        )
    
    if(grant_type == GrantType.CLIENT_CREDENTIALS):
        return TokenResponse(
            access_token="",
            token_type=TokenType.BEARER,
            expires_in=300
        )
    else:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=ErrorMessage(
            error_code=ErrorCode.ACCESS_DENIED,
            error_description="invalid credentials"
        ))
