from typing import Annotated, List
from fastapi import APIRouter, status, Path

from ...utils.schemas.client import ClientAPIIn, ClientAPIOut, Client
from ...utils.managers.auth import AuthManager
from ...utils.managers.client import ClientManager

router = APIRouter(tags=["management", "scope"])
auth_manager = AuthManager()
client_manager: ClientManager = auth_manager.client_manager


@router.post(
    "/client",
    status_code=status.HTTP_201_CREATED,
)
async def create_client(client_in: ClientAPIIn) -> None:
    await client_manager.create_client(client=client_in.to_client())


@router.put(
    "/client/{id}",
    status_code=status.HTTP_200_OK,
)
async def update_client(
    client_id: Annotated[str, Path(alias="id")], client_in: ClientAPIIn
) -> None:
    await client_manager.update_client(
        client_id=client_id, client=client_in.to_client()
    )


@router.get(
    "/client/{id}",
    status_code=status.HTTP_200_OK,
    response_model=ClientAPIOut,
    response_model_exclude_none=True,
)
async def get_client(client_id: Annotated[str, Path(alias="id")]):
    client: Client = await client_manager.get_client(client_id=client_id)
    return client.to_output()


@router.get(
    "/clients",
    status_code=status.HTTP_200_OK,
    response_model_exclude_none=True,
)
async def get_clients() -> List[ClientAPIOut]:
    clients: List[Client] = await client_manager.get_clients()
    return [c.to_output() for c in clients]
