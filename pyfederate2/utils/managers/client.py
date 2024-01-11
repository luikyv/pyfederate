from typing import List
from abc import ABC, abstractmethod

from ..schemas.client import Client


class ClientManager(ABC):
    @abstractmethod
    async def create_client(self, client: Client) -> None:
        """
        Throws:
            exceptions.EntityAlreadyExistsException
        """
        pass

    @abstractmethod
    async def update_client(self, client_id: str, client: Client) -> None:
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
    async def get_clients(self) -> List[Client]:
        pass

    @abstractmethod
    async def delete_client(self, client_id: str) -> None:
        pass
