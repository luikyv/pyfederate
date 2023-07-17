import typing
from fastapi import APIRouter, status

from ..utils import schemas, constants, exceptions
from ..auth_manager import manager as auth_manager

router = APIRouter(
    tags=["management"]
)

#################### Token Model ####################


@router.post(
    "/token_model",
    status_code=status.HTTP_201_CREATED,
)
async def create_token_model(token_model_input: schemas.TokenModelIn) -> schemas.TokenModelOut:

    token_model: schemas.TokenModel = await auth_manager.token_model_manager.create_token_model(token_model=token_model_input.to_upsert())
    return token_model.to_output()


@router.get(
    "/token_model/{token_model_id}",
    status_code=status.HTTP_200_OK,
)
async def get_token_model(token_model_id: str) -> schemas.TokenModelOut:
    token_model: schemas.TokenModel = await auth_manager.token_model_manager.get_token_model(token_model_id=token_model_id)
    return token_model.to_output()


@router.get(
    "/token_models",
    status_code=status.HTTP_200_OK,
)
async def get_token_models() -> typing.List[schemas.TokenModelOut]:
    token_models: typing.List[schemas.TokenModel] = await auth_manager.token_model_manager.get_token_models()
    return [token_model.to_output() for token_model in token_models]


@router.delete(
    "/token_model/{token_model_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def delete_token_model(token_model_id: str) -> None:
    await auth_manager.token_model_manager.delete_token_model(token_model_id=token_model_id)

#################### Scope ####################


@router.post(
    "/scope",
    status_code=status.HTTP_201_CREATED,
)
async def create_scope(scope_in: schemas.ScopeIn) -> None:
    await auth_manager.scope_manager.create_scope(scope=scope_in.to_upsert())


@router.get(
    "/scope/{scope_name}",
    status_code=status.HTTP_200_OK,
)
async def get_scope(scope_name: str) -> schemas.ScopeOut:
    scope: schemas.Scope = await auth_manager.scope_manager.get_scope(scope_name=scope_name)
    return scope.to_output()


@router.get(
    "/scopes",
    status_code=status.HTTP_200_OK,
)
async def get_scopes() -> typing.List[schemas.ScopeOut]:
    scopes: typing.List[schemas.Scope] = await auth_manager.scope_manager.get_scopes()
    return [scope.to_output() for scope in scopes]


@router.delete(
    "/scope/{scope_name}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def delete_client(scope_name: str) -> None:
    await auth_manager.scope_manager.delete_scope(scope_name=scope_name)

#################### Client ####################


@router.post(
    "/client",
    status_code=status.HTTP_201_CREATED,
    response_model_exclude_none=True,
)
async def create_client(client_in: schemas.ClientIn) -> schemas.ClientOut:
    created_client = await auth_manager.client_manager.create_client(client=client_in.to_upsert())
    return created_client.to_output()


@router.get(
    "/client/{client_id}",
    status_code=status.HTTP_200_OK,
    response_model=schemas.ClientOut,
    response_model_exclude_none=True,
)
async def get_client(client_id: str):
    try:
        client: schemas.Client = await auth_manager.client_manager.get_client(client_id=client_id)
    except exceptions.ClientDoesNotExist:
        raise exceptions.HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            error=constants.ErrorCode.ACCESS_DENIED,
            error_description="invalid credentials"
        )

    return client.to_output()


@router.get(
    "/clients",
    status_code=status.HTTP_200_OK,
    response_model_exclude_none=True,
)
async def get_clients() -> typing.List[schemas.ClientOut]:
    clients: typing.List[schemas.Client] = await auth_manager.client_manager.get_clients()
    return [
        c.to_output() for c in clients
    ]
