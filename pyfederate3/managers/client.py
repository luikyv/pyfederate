from typing import List
from abc import ABC, abstractmethod

from ..schemas.client import ClientIn, ClientOut
from ..utils.client import Client


class ClientManager(ABC):
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
    async def get_client(self, client_id: str) -> Client:
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
