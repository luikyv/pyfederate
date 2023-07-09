from abc import ABC, abstractmethod

from .schemas import Client

class ClientManager(ABC):

    @abstractmethod
    async def create_client(self, client: Client) -> None:
        """
        Throws:
            exceptions.ClientAlreadyExists
        """
        pass

    @abstractmethod
    async def update_client(self, client: Client) -> None:
        """
        Throws:
            exceptions.ClientDoesNotExist
        """
        pass
    
    @abstractmethod
    async def get_client(self, client_id: str) -> Client:
        """
        Throws:
            exceptions.ClientDoesNotExist
        """
        pass
    
    @abstractmethod
    async def delete_client(self, client_id: str) -> None:
        """
        Throws:
            exceptions.ClientDoesNotExist
        """
        pass