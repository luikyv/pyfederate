from typing import List
from abc import ABC, abstractmethod

from ..schemas.scope import ScopeIn, ScopeOut


class ScopeManager(ABC):
    @abstractmethod
    async def create_scope(self, scope: ScopeIn) -> None:
        """
        Throws:
            EntityAlreadyExistsException
        """
        pass

    @abstractmethod
    async def update_scope(self, scope_name: str, scope: ScopeIn) -> None:
        """
        Throws:
            EntityDoesNotExistException
        """
        pass

    @abstractmethod
    async def get_scope_out(self, scope_name: str) -> ScopeOut:
        """
        Throws:
            EntityDoesNotExistException
        """
        pass

    @abstractmethod
    async def get_scopes_out(self) -> List[ScopeOut]:
        pass

    @abstractmethod
    async def delete_scope(self, scope_name: str) -> None:
        pass
