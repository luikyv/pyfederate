from typing import List
from fastapi import APIRouter, status

from ..schemas.scope import ScopeIn, ScopeOut
from ..crud.auth import AuthCRUDManager

router = APIRouter(tags=["management"])
auth_manager = AuthCRUDManager()


@router.post(
    "/scope",
    status_code=status.HTTP_201_CREATED,
)
async def create_scope(
    scope_in: ScopeIn,
) -> None:
    await auth_manager.scope_manager.create_scope(scope=scope_in)


@router.put(
    "/scope/{name}",
    status_code=status.HTTP_200_OK,
)
async def update_scope(
    name: str,
    scope_in: ScopeIn,
) -> None:
    await auth_manager.scope_manager.update_scope(scope_name=name, scope=scope_in)


@router.get(
    "/scope/{name}",
    status_code=status.HTTP_200_OK,
)
async def get_scope(
    name: str,
) -> ScopeOut:
    return await auth_manager.scope_manager.get_scope_out(scope_name=name)


@router.get(
    "/scopes",
    status_code=status.HTTP_200_OK,
)
async def get_scopes() -> List[ScopeOut]:
    return await auth_manager.scope_manager.get_scopes_out()


@router.delete(
    "/scope/{name}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def delete_client(name: str) -> None:
    await auth_manager.scope_manager.delete_scope(scope_name=name)
