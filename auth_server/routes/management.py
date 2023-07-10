from dataclasses import asdict
from typing import List
from fastapi import APIRouter, status
from fastapi.responses import JSONResponse

from ..utils import schemas, constants, exceptions
from ..auth_manager import manager as auth_manager

router = APIRouter(
    tags = ["management"]
)

#################### Scope ####################

@router.post(
    "/scope",
    status_code=status.HTTP_201_CREATED,
    tags=["scope"]
)
async def create_scope(scope: schemas.ScopeIn) -> None:
    await auth_manager.scope_manager.create_scope(scope=schemas.Scope(**asdict(scope)))

@router.get(
    "/scope/{scope_name}",
    status_code=status.HTTP_200_OK,
    tags=["scope"]
)
async def get_scope(scope_name: str) -> schemas.ScopeOut:
    scope: schemas.Scope = await auth_manager.scope_manager.get_scope(scope_name=scope_name)
    return schemas.ScopeOut(**asdict(scope))

@router.get(
    "/scopes",
    status_code=status.HTTP_200_OK,
    tags=["scope"]
)
async def get_scopes() -> List[schemas.ScopeOut]:
    scopes: List[schemas.Scope] = await auth_manager.scope_manager.get_scopes()
    return [schemas.ScopeOut(**asdict(scope)) for scope in scopes]

@router.delete(
    "/scope/{scope_name}",
    status_code=status.HTTP_204_NO_CONTENT,
    tags=["scope"]
)
async def delete_client(scope_name: str) -> None:
    await auth_manager.scope_manager.delete_scope(scope_name=scope_name)

#################### Client ####################

@router.post(
    "/client",
    status_code=status.HTTP_201_CREATED,
    tags=["client"]
)
async def create_client(client: schemas.ClientIn) -> schemas.ClientOut:
    created_client = await auth_manager.client_manager.create_client(client=schemas.ClientUpsert(**asdict(client)))
    return schemas.ClientOut(
        id=created_client.id,
        scopes=created_client.scopes
    )

@router.get(
    "/client/{client_id}",
    status_code=status.HTTP_200_OK,
    tags=["client"],
    response_model=schemas.ClientOut
)
async def get_client(client_id: str):
    try:
        client: schemas.Client = await auth_manager.client_manager.get_client(client_id=client_id)
    except exceptions.ClientDoesNotExist:
        raise exceptions.HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            error_code=constants.ErrorCode.ACCESS_DENIED,
            detail="invalid credentials"
        )
    
    return schemas.ClientOut(
        id=client.id,
        scopes=client.scopes
    )

@router.get(
    "/clients",
    status_code=status.HTTP_200_OK,
    tags=["client"]
)
async def get_clients() -> List[schemas.ClientOut]:
    clients: List[schemas.Client] = await auth_manager.client_manager.get_clients()
    return [
        schemas.ClientOut(
            id=c.id,
            scopes=c.scopes
        ) for c in clients
    ]