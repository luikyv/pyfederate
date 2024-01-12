from typing import Dict, List
from abc import ABC, abstractmethod

from .token import InternalTokenModelManager
from ..schemas.client import ClientIn, ClientOut, ClientAuthnInfoIn, ClientAuthnInfoOut
from ..utils.client import Client
from ..utils.telemetry import get_logger
from ..utils.tools import remove_oldest_item, hash_secret
from .exceptions import EntityAlreadyExistsException, EntityDoesNotExistException

logger = get_logger(__name__)


class InternalClientManager(ABC):
    @abstractmethod
    async def get_client(self, client_id: str) -> Client:
        """
        Throws:
            exceptions.EntityDoesNotExistException
        """
        pass


class APIClientManager(ABC):
    @abstractmethod
    async def create_client(self, client: ClientIn) -> None:
        """
        Throws:
            exceptions.EntityAlreadyExistsException
        """
        pass

    @abstractmethod
    async def update_client(self, client_id: str, client: ClientIn) -> None:
        """
        Throws:
            exceptions.EntityDoesNotExistException
        """
        pass

    @abstractmethod
    async def get_client_out(self, client_id: str) -> ClientOut:
        """
        Throws:
            exceptions.EntityDoesNotExistException
        """
        pass

    @abstractmethod
    async def get_clients_out(self) -> List[ClientOut]:
        pass

    @abstractmethod
    async def delete_client(self, client_id: str) -> None:
        pass


class InMemoryClientManager(APIClientManager, InternalClientManager):
    def __init__(
        self, token_manager: InternalTokenModelManager, max_number: int = 10
    ) -> None:
        self._max_number = max_number
        self._token_manager = token_manager
        self._clients: Dict[str, ClientIn] = {}

    async def create_client(self, client: ClientIn) -> None:

        if client.client_id in self._clients:
            logger.info(f"Client with ID: {client.client_id} already exists")
            raise EntityAlreadyExistsException()
        if len(self._clients) >= self._max_number:
            remove_oldest_item(self._clients)

        self._clients[client.client_id] = client

    async def update_client(self, client: ClientIn) -> None:

        if client.client_id not in self._clients:
            logger.info(f"Client with ID: {client.client_id} does not exist")
            raise EntityDoesNotExistException()

        self._clients[client.client_id] = client

    @abstractmethod
    async def get_client(self, client_id: str) -> Client:
        """
        Throws:
            exceptions.EntityDoesNotExistException
        """
        raise NotImplementedError()

    async def get_client_out(self, client_id: str) -> ClientOut:

        client: ClientIn | None = self._clients.get(client_id, None)
        if not client:
            logger.info(f"Client with ID: {client_id} does not exist")
            raise EntityDoesNotExistException()

        return ClientOut(
            **client.model_dump(),
            authn_info=ClientAuthnInfoOut(
                authn_info=client.authn_info.authn_info,
                hashed_secret=hash_secret(client.authn_info.secret)
                if client.authn_info.secret
                else None,
            ),
        )

    async def get_clients_out(self) -> List[ClientOut]:
        return [
            ClientOut(
                **client.model_dump(),
                authn_info=ClientAuthnInfoOut(
                    authn_info=client.authn_info.authn_info,
                    hashed_secret=hash_secret(client.authn_info.secret)
                    if client.authn_info.secret
                    else None,
                ),
            )
            for client in self._clients.values()
        ]

    async def delete_client(self, client_id: str) -> None:
        self._clients.pop(client_id)
