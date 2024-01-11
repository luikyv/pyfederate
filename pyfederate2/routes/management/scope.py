from typing import List
from fastapi import APIRouter, status

from ...utils.schemas.scope import ScopeAPIIn, ScopeAPIOut, Scope
from ...utils.managers.auth import AuthManager
from ...utils.managers.scope import ScopeManager

router = APIRouter(tags=["management", "scope"])
auth_manager = AuthManager()
scope_manager: ScopeManager = auth_manager.scope_manager


@router.post(
    "/scope",
    status_code=status.HTTP_201_CREATED,
)
async def create_scope(
    scope_in: ScopeAPIIn,
) -> None:
    await scope_manager.create_scope(scope=scope_in)


@router.put(
    "/scope/{name}",
    status_code=status.HTTP_200_OK,
)
async def update_scope(
    name: str,
    scope_in: ScopeAPIIn,
) -> None:
    await scope_manager.update_scope(scope_name=name, scope=scope_in)


@router.get(
    "/scope/{name}",
    status_code=status.HTTP_200_OK,
)
async def get_scope(
    name: str,
) -> ScopeAPIOut:
    scope: Scope = await scope_manager.get_scope(scope_name=name)
    return scope.to_output()


@router.get(
    "/scopes",
    status_code=status.HTTP_200_OK,
)
async def get_scopes() -> List[ScopeAPIOut]:
    scopes: List[Scope] = await scope_manager.get_scopes()
    return [scope.to_output() for scope in scopes]


@router.delete(
    "/scope/{name}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def delete_client(name: str) -> None:
    await scope_manager.delete_scope(scope_name=name)
