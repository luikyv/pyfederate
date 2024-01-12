from typing import Annotated, List
from fastapi import APIRouter, status, Path, HTTPException

from ..schemas.client import ClientIn, ClientOut
from ..managers.auth import AuthManager
from ..managers.client import ClientManager

router = APIRouter(tags=["management", "client"])
auth_manager = AuthManager()
client_manager: ClientManager = auth_manager.client_manager


@router.post(
    "/client",
    status_code=status.HTTP_201_CREATED,
)
async def create_client(client_in: ClientIn) -> None:
    await client_manager.create_client(client=client_in)


@router.put(
    "/client/{id}",
    status_code=status.HTTP_200_OK,
)
async def update_client(
    client_id: Annotated[str, Path(alias="id")], client_in: ClientIn
) -> None:
    await client_manager.update_client(client_id=client_id, client=client_in)


@router.get(
    "/client/{id}",
    status_code=status.HTTP_200_OK,
    response_model=ClientOut,
    response_model_exclude_none=True,
)
async def get_client(client_id: Annotated[str, Path(alias="id")]):
    return await client_manager.get_client(client_id=client_id)


@router.get(
    "/clients",
    status_code=status.HTTP_200_OK,
    response_model_exclude_none=True,
)
async def get_clients() -> List[ClientOut]:
    return await client_manager.get_clients_out()
