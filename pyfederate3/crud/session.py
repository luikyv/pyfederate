from typing import Dict, List
from abc import ABC, abstractmethod

from ..utils.telemetry import get_logger
from ..schemas.auth import AuthnSession
from ..schemas.token import TokenInfo
from ..utils.tools import remove_oldest_item
from .exceptions import EntityAlreadyExistsException, EntityDoesNotExistException

logger = get_logger(__name__)


class AuthnSessionCRUDManager(ABC):
    @abstractmethod
    async def create_session(self, session: AuthnSession) -> None:
        """
        Throws:
            exceptions.EntityAlreadyExists
        """
        pass

    @abstractmethod
    async def update_session(self, session: AuthnSession) -> None:
        """
        Throws:
            exceptions.EntityAlreadyExists
        """
        pass

    @abstractmethod
    async def get_session_by_authz_code(self, authz_code: str) -> AuthnSession:
        """
        Throws:
            exceptions.EntityDoesNotExist
        """
        pass

    @abstractmethod
    async def get_session_by_callback_id(self, callback_id: str) -> AuthnSession:
        """
        Throws:
            exceptions.EntityDoesNotExist
        """
        pass

    @abstractmethod
    async def get_session_by_request_uri(self, request_uri: str) -> AuthnSession:
        """
        Throws:
            exceptions.EntityDoesNotExist
        """
        pass

    @abstractmethod
    async def delete_session(self, session_id: str) -> None:
        """
        Throws:
            exceptions.EntityDoesNotExist
        """
        pass


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


class InMemorySessionCRUDManager(AuthnSessionCRUDManager):
    def __init__(self, max_number: int = 100) -> None:
        self._max_number = max_number
        self._sessions: Dict[str, AuthnSession] = {}

    async def create_session(self, session: AuthnSession) -> None:

        if session.id in self._sessions:
            logger.info(f"The session ID: {session.id} already exists")
            raise EntityAlreadyExistsException()

        if len(self._sessions) >= self._max_number:
            remove_oldest_item(self._sessions)
        self._sessions[session.id] = session

    async def update_session(self, session: AuthnSession) -> None:

        if session.id not in self._sessions:
            logger.info(f"The session ID: {session.id} does not exist")
            raise EntityDoesNotExistException()

        self._sessions[session.id] = session

    async def get_session_by_authz_code(self, authz_code: str) -> AuthnSession:

        raise NotImplementedError()
        filtered_sessions: List[AuthnSession] = list(
            filter(
                lambda session: session.authorization_code == authz_code,
                self._sessions.values(),
            )
        )
        if len(filtered_sessions) != 1:
            logger.info(
                f"The authorization code: {authz_code} has no associated session"
            )
            raise EntityDoesNotExistException()

        return filtered_sessions[0]

    async def get_session_by_callback_id(self, callback_id: str) -> AuthnSession:

        filtered_sessions: List[AuthnSession] = list(
            filter(
                lambda session: session.callback_id == callback_id,
                self._sessions.values(),
            )
        )
        if len(filtered_sessions) != 1:
            logger.info(f"The callback ID: {callback_id} has no associated session")
            raise EntityDoesNotExistException()

        return filtered_sessions[0]

    async def get_session_by_request_uri(self, request_uri: str) -> AuthnSession:
        raise NotImplementedError()
        filtered_sessions: List[AuthnSession] = list(
            filter(
                lambda session: session.request_uri == request_uri,
                self._sessions.values(),
            )
        )
        if len(filtered_sessions) != 1:
            logger.info(f"The request URI: {request_uri} has no associated session")
            raise EntityDoesNotExistException()

        return filtered_sessions[0]

    async def delete_session(self, session_id: str) -> None:
        self._sessions.pop(session_id)


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
