from typing import Dict, List
from abc import ABC, abstractmethod

from ..schemas.scope import ScopeIn, ScopeOut
from ..utils.telemetry import get_logger
from ..utils.tools import remove_oldest_item
from .exceptions import EntityAlreadyExistsException, EntityDoesNotExistException

logger = get_logger(__name__)


class APIScopeManager(ABC):
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


class InMemoryScopeManager(APIScopeManager):
    def __init__(self, max_number: int = 100) -> None:
        self._max_number = max_number
        self._scopes: Dict[str, ScopeIn] = {}

    async def create_scope(self, scope: ScopeIn) -> None:

        if scope.name in self._scopes:
            logger.info(f"{scope.name} already exists")
            raise EntityAlreadyExistsException()

        if len(self._scopes) >= self._max_number:
            remove_oldest_item(self._scopes)
        self._scopes[scope.name] = scope

    async def update_scope(self, scope: ScopeIn) -> None:

        if scope.name not in self._scopes:
            logger.info(f"{scope.name} does not exist")
            raise EntityDoesNotExistException()

        self._scopes[scope.name] = scope

    async def get_scope_out(self, scope_name: str) -> ScopeOut:

        if scope_name not in self._scopes:
            logger.info(f"{scope_name} does not exist")
            raise EntityDoesNotExistException()

        scope: ScopeIn = self._scopes[scope_name]
        return ScopeOut(name=scope.name, description=scope.description)

    async def get_scopes(self) -> List[ScopeOut]:
        return [
            ScopeOut(name=scope.name, description=scope.description)
            for scope in self._scopes.values()
        ]

    async def delete_scope(self, scope_name: str) -> None:
        self._scopes.pop(scope_name)
