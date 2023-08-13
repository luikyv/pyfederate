from typing import Annotated, List
from fastapi import APIRouter, status, Depends
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import secrets

from ..utils import schemas, constants, exceptions
from ..auth_manager import manager as manager

router = APIRouter(tags=["management"])

#################### Credentials ####################

security = HTTPBasic()


def validate_credentials(
    credentials: Annotated[HTTPBasicCredentials, Depends(security)]
) -> None:

    correct_username_bytes = b"admin"
    correct_password_bytes = b"password"

    current_username_bytes = credentials.username.encode("utf8")
    is_correct_username = secrets.compare_digest(
        current_username_bytes, correct_username_bytes
    )
    current_password_bytes = credentials.password.encode("utf8")
    is_correct_password = secrets.compare_digest(
        current_password_bytes, correct_password_bytes
    )
    if not (is_correct_username and is_correct_password):
        raise exceptions.JsonResponseException(
            error=constants.ErrorCode.NOT_UNAUTHORIZED,
            error_description="invalid credentials",
        )


#################### Token Model ####################


@router.post(
    "/token_model",
    status_code=status.HTTP_201_CREATED,
)
async def create_token_model(
    token_model_input: schemas.TokenModelIn,
    _: Annotated[None, Depends(validate_credentials)],
) -> schemas.TokenModelOut:
    token_model: schemas.TokenModel = (
        await manager.token_model_manager.create_token_model(
            token_model=token_model_input.to_upsert()
        )
    )
    return token_model.to_output()


@router.get(
    "/token_model/{token_model_id}",
    status_code=status.HTTP_200_OK,
)
async def get_token_model(
    token_model_id: str, _: Annotated[None, Depends(validate_credentials)]
) -> schemas.TokenModelOut:
    token_model: schemas.TokenModel = await manager.token_model_manager.get_token_model(
        token_model_id=token_model_id
    )
    return token_model.to_output()


@router.get(
    "/token_models",
    status_code=status.HTTP_200_OK,
)
async def get_token_models(
    _: Annotated[None, Depends(validate_credentials)]
) -> List[schemas.TokenModelOut]:
    token_models: List[
        schemas.TokenModel
    ] = await manager.token_model_manager.get_token_models()
    return [token_model.to_output() for token_model in token_models]


@router.delete(
    "/token_model/{token_model_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def delete_token_model(
    token_model_id: str, _: Annotated[None, Depends(validate_credentials)]
) -> None:
    await manager.token_model_manager.delete_token_model(token_model_id=token_model_id)


#################### Scope ####################


@router.post(
    "/scope",
    status_code=status.HTTP_201_CREATED,
)
async def create_scope(
    scope_in: schemas.ScopeIn, _: Annotated[None, Depends(validate_credentials)]
) -> None:
    await manager.scope_manager.create_scope(scope=scope_in.to_upsert())


@router.get(
    "/scope/{scope_name}",
    status_code=status.HTTP_200_OK,
)
async def get_scope(
    scope_name: str, _: Annotated[None, Depends(validate_credentials)]
) -> schemas.ScopeOut:
    scope: schemas.Scope = await manager.scope_manager.get_scope(scope_name=scope_name)
    return scope.to_output()


@router.get(
    "/scopes",
    status_code=status.HTTP_200_OK,
)
async def get_scopes(
    _: Annotated[None, Depends(validate_credentials)]
) -> List[schemas.ScopeOut]:
    scopes: List[schemas.Scope] = await manager.scope_manager.get_scopes()
    return [scope.to_output() for scope in scopes]


@router.delete(
    "/scope/{scope_name}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def delete_client(
    scope_name: str, _: Annotated[None, Depends(validate_credentials)]
) -> None:
    await manager.scope_manager.delete_scope(scope_name=scope_name)


#################### Client ####################


@router.post(
    "/client",
    status_code=status.HTTP_201_CREATED,
    response_model_exclude_none=True,
)
async def create_client(
    client_in: schemas.ClientIn, _: Annotated[None, Depends(validate_credentials)]
) -> schemas.ClientOut:
    created_client = await manager.client_manager.create_client(
        client=client_in.to_upsert()
    )
    return created_client.to_output()


@router.get(
    "/client/{client_id}",
    status_code=status.HTTP_200_OK,
    response_model=schemas.ClientOut,
    response_model_exclude_none=True,
)
async def get_client(client_id: str, _: Annotated[None, Depends(validate_credentials)]):
    client: schemas.Client = await manager.client_manager.get_client(
        client_id=client_id
    )
    return client.to_output()


@router.get(
    "/clients",
    status_code=status.HTTP_200_OK,
    response_model_exclude_none=True,
)
async def get_clients(
    _: Annotated[None, Depends(validate_credentials)]
) -> List[schemas.ClientOut]:
    clients: List[schemas.Client] = await manager.client_manager.get_clients()
    return [c.to_output() for c in clients]
