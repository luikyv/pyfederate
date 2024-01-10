from typing import Annotated, List
from fastapi import Path, APIRouter, status, Depends
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from . import security

from ...utils.schemas.scope import ScopeAPIIn, ScopeAPIOut

router = APIRouter(tags=["management"])

######################################## Endpoints ########################################


@router.post(
    "/scope",
    status_code=status.HTTP_201_CREATED,
)
async def create_scope(
    scope_in: ScopeAPIIn,
    _: Annotated[None, Depends(security.validate_credentials)],
) -> None:
    raise NotImplementedError()


@router.get(
    "/scope/{name}",
    status_code=status.HTTP_200_OK,
)
async def get_scope(
    name: str, _: Annotated[None, Depends(security.validate_credentials)]
) -> ScopeAPIOut:
    raise NotImplementedError()


@router.get(
    "/scopes",
    status_code=status.HTTP_200_OK,
)
async def get_scopes(
    _: Annotated[None, Depends(security.validate_credentials)]
) -> List[ScopeAPIOut]:
    raise NotImplementedError()


@router.delete(
    "/scope/{name}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def delete_client(
    name: str, _: Annotated[None, Depends(security.validate_credentials)]
) -> None:
    raise NotImplementedError()
