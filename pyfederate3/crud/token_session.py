from typing import Dict, List
from abc import ABC, abstractmethod

from ..utils.telemetry import get_logger
from ..schemas.auth import AuthnSession
from ..schemas.token import TokenInfo
from ..utils.tools import remove_oldest_item
from .exceptions import EntityAlreadyExistsException, EntityDoesNotExistException

logger = get_logger(__name__)

class TokenSessionCRUDManager(ABC):
    pass

    @abstractmethod
    async def create_token_session(self, info: TokenInfo) -> None:
        """
        Throws:
            exceptions.EntityAlreadyExists
        """
        pass

    @abstractmethod
    async def update_token_session(self, info: TokenInfo) -> None:
        """
        Throws:
            exceptions.EntityDoesNotExist
        """
        pass

    @abstractmethod
    async def get_token_session_by_id(self, token_id: str) -> TokenInfo:
        """
        Throws:
            exceptions.EntityDoesNotExist
        """
        pass

    @abstractmethod
    async def get_token_session_by_refresh_token(self, refresh_token: str) -> TokenInfo:
        """
        Throws:
            exceptions.EntityDoesNotExist
        """
        pass

    @abstractmethod
    async def delete_token_session(self, session_id: str) -> None:
        """
        Throws:
            exceptions.EntityDoesNotExist
        """
        pass


class InMemoryTokenSessionCRUDManager(TokenSessionCRUDManager):
    def __init__(self, max_number: int = 100) -> None:
        self._max_number = max_number
        self._token_sessions: Dict[str, TokenInfo] = {}

    async def create_token_session(self, session: TokenInfo) -> None:
        if session.id in self._token_sessions:
            logger.info(f"The token session ID: {session.id} already exists")
            raise EntityAlreadyExistsException()

        if len(self._token_sessions) >= self._max_number:
            remove_oldest_item(self._token_sessions)
        self._token_sessions[session.id] = session

    async def update_token_session(self, session: TokenInfo) -> None:

        if session.id not in self._token_sessions:
            logger.info(f"The token ID: {session.id} has no associated session")
            raise EntityDoesNotExistException()

        self._token_sessions[session.id] = session

    async def get_token_session_by_id(self, token_id: str) -> TokenInfo:
        session: TokenInfo | None = self._token_sessions.get(token_id, None)
        if session is None:
            logger.info(f"The token ID: {token_id} has no associated session")
            raise EntityDoesNotExistException()
        return session

    async def get_token_session_by_refresh_token(self, refresh_token: str) -> TokenInfo:
        raise NotImplementedError()
        filtered_token_sessions: List[TokenInfo] = list(
            filter(
                lambda session: session.refresh_token == refresh_token,
                self._token_sessions.values(),
            )
        )
        if len(filtered_token_sessions) != 1:
            logger.info(f"The refresh token: {refresh_token} has no associated session")
            raise exceptions.EntityDoesNotExistException()

        return filtered_token_sessions[0]

    async def delete_token_session(self, session_id: str) -> None:
        self._token_sessions.pop(session_id)
