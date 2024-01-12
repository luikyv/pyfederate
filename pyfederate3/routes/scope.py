from typing import List
from fastapi import APIRouter, status

from ..schemas.scope import ScopeIn, ScopeOut
from ..managers.auth import AuthManager
from ..managers.scope import APIScopeManager

router = APIRouter(tags=["management", "scope"])
auth_manager = AuthManager()
scope_manager: APIScopeManager = auth_manager.scope_manager


@router.post(
    "/scope",
    status_code=status.HTTP_201_CREATED,
)
async def create_scope(
    scope_in: ScopeIn,
) -> None:
    await scope_manager.create_scope(scope=scope_in)


@router.put(
    "/scope/{name}",
    status_code=status.HTTP_200_OK,
)
async def update_scope(
    name: str,
    scope_in: ScopeIn,
) -> None:
    await scope_manager.update_scope(scope_name=name, scope=scope_in)


@router.get(
    "/scope/{name}",
    status_code=status.HTTP_200_OK,
)
async def get_scope(
    name: str,
) -> ScopeOut:
    return await scope_manager.get_scope_out(scope_name=name)


@router.get(
    "/scopes",
    status_code=status.HTTP_200_OK,
)
async def get_scopes() -> List[ScopeOut]:
    return await scope_manager.get_scopes_out()


@router.delete(
    "/scope/{name}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def delete_client(name: str) -> None:
    await scope_manager.delete_scope(scope_name=name)
