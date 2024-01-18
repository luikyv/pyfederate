from typing import Annotated, List
from fastapi import APIRouter, status, Form, Depends, Request, Response

from ..crud.auth import AuthCRUDManager
from ..utils.telemetry import get_logger
from ..schemas.oauth import TokenResponse, GrantContext
from ..utils.constants import GrantType, CORRELATION_ID_HEADER_TYPE
from ..utils.oauth import get_scopes_as_form
from ..utils.client import Client
from ..utils.oauth import get_authenticated_client, grant_handlers

logger = get_logger(__name__)

router = APIRouter(tags=["oauth"])
auth_manager = AuthCRUDManager.get_manager()


@router.post(
    "/token",
    response_model_exclude_none=True,
    status_code=status.HTTP_200_OK,
)
async def get_token(
    client: Annotated[Client, Depends(get_authenticated_client)],
    grant_type: Annotated[GrantType, Form()],
    scopes: Annotated[List[str], Depends(get_scopes_as_form)],
    code: Annotated[str | None, Form()] = None,
    redirect_uri: Annotated[str | None, Form()] = None,
    refresh_token: Annotated[str | None, Form()] = None,
    code_verifier: Annotated[str | None, Form(min_length=43, max_length=128)] = None,
    correlation_id: CORRELATION_ID_HEADER_TYPE = None,
) -> TokenResponse:
    grant_context = GrantContext(
        grant_type=grant_type,
        scopes=scopes,
        redirect_uri=redirect_uri,
        refresh_token=refresh_token,
        authz_code=code,
        code_verifier=code_verifier,
        correlation_id=correlation_id,
    )
    return await grant_handlers[grant_type](grant_context, client)
