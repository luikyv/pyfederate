from typing import List
from abc import ABC, abstractmethod

from .schemas import ClientUpsert, Client, Scope

class ClientManager(ABC):

    @abstractmethod
    async def create_client(self, client: ClientUpsert) -> Client:
        """
        Throws:
            exceptions.ClientAlreadyExists
        """
        pass

    @abstractmethod
    async def update_client(self, client: Client) -> Client:
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
    async def get_clients(self) -> List[Client]:
        pass
    
    @abstractmethod
    async def delete_client(self, client_id: str) -> None:
        pass

class ScopeManager(ABC):

    @abstractmethod
    async def create_scope(self, scope: Scope) -> None:
        """
        Throws:
            exceptions.ScopeAlreadyExists
        """
        pass

    @abstractmethod
    async def update_scope(self, scope: Scope) -> None:
        """
        Throws:
            exceptions.ScopeDoesNotExist
        """
        pass
    
    @abstractmethod
    async def get_scope(self, scope_name: str) -> Scope:
        """
        Throws:
            exceptions.ScopeDoesNotExist
        """
        pass

    @abstractmethod
    async def get_scopes(self) -> List[Scope]:
        pass
    
    @abstractmethod
    async def delete_scope(self, scope_name: str) -> None:
        pass