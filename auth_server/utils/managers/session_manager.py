import typing
from abc import ABC, abstractmethod

from .. import schemas, telemetry, tools
from .. import exceptions

logger = telemetry.get_logger(__name__)

######################################## Interfaces ########################################


class SessionManager(ABC):
    @abstractmethod
    async def create_session(self, session: schemas.AuthnSession) -> None:
        """
        Throws:
            exceptions.SessionInfoAlreadyExists
        """
        pass

    @abstractmethod
    async def create_token_session(self, session: schemas.TokenSession) -> None:
        """
        Throws:
            exceptions.TokenSessionAlreadyExists
        """
        pass

    @abstractmethod
    async def update_session(self, session: schemas.AuthnSession) -> None:
        """
        Throws:
            exceptions.SessionInfoDoesNotExist
        """
        pass

    @abstractmethod
    async def update_token_session(self, session: schemas.TokenSession) -> None:
        """
        Throws:
            exceptions.TokenSessionDoesNotExist
        """
        pass

    @abstractmethod
    async def get_session_by_authz_code(self, authz_code: str) -> schemas.AuthnSession:
        """
        Throws:
            exceptions.SessionInfoDoesNotExist
        """
        pass

    @abstractmethod
    async def get_session_by_callback_id(
        self, callback_id: str
    ) -> schemas.AuthnSession:
        """
        Throws:
            exceptions.SessionInfoDoesNotExist
        """
        pass

    @abstractmethod
    async def get_token_session_by_id(self, token_id: str) -> schemas.TokenSession:
        """
        Throws:
            exceptions.TokenSessionDoesNotExist
        """
        pass

    @abstractmethod
    async def get_token_session_by_refresh_token(
        self, refresh_token: str
    ) -> schemas.TokenSession:
        """
        Throws:
            exceptions.TokenSessionDoesNotExist
        """
        pass

    @abstractmethod
    async def delete_session(self, session_id: str) -> None:
        """
        Throws:
            exceptions.SessionInfoDoesNotExist
        """
        pass


######################################## Implementations ########################################


class InMemorySessionManager(SessionManager):
    def __init__(self, max_number: int = 100) -> None:
        self._max_number = max_number
        self._sessions: typing.Dict[str, schemas.AuthnSession] = {}
        self._token_sessions: typing.Dict[str, schemas.TokenSession] = {}

    async def create_session(self, session: schemas.AuthnSession) -> None:

        if session.id in self._sessions:
            logger.info(f"The session ID: {session.id} already exists")
            raise exceptions.EntityAlreadyExistsException()

        if len(self._sessions) >= self._max_number:
            tools.remove_oldest_item(self._sessions)
        self._sessions[session.id] = session

    async def create_token_session(self, session: schemas.TokenSession) -> None:
        if session.token_id in self._sessions:
            logger.info(f"The token session ID: {session.token_id} already exists")
            raise exceptions.EntityAlreadyExistsException()

        if len(self._token_sessions) >= self._max_number:
            tools.remove_oldest_item(self._token_sessions)
        self._token_sessions[session.token_id] = session

    async def update_session(self, session: schemas.AuthnSession) -> None:

        if session.id not in self._sessions:
            logger.info(f"The session ID: {session.id} does not exist")
            raise exceptions.EntityDoesNotExistException()

        self._sessions[session.id] = session

    async def update_token_session(self, session: schemas.TokenSession) -> None:

        if session.token_id not in self._token_sessions:
            logger.info(f"The token ID: {session.token_id} has no associated session")
            raise exceptions.EntityDoesNotExistException()

        self._token_sessions[session.token_id] = session

    async def get_session_by_authz_code(self, authz_code: str) -> schemas.AuthnSession:

        filtered_sessions: typing.List[schemas.AuthnSession] = list(
            filter(
                lambda session: session.authz_code == authz_code,
                self._sessions.values(),
            )
        )
        if len(filtered_sessions) != 1:
            logger.info(
                f"The authorization code: {authz_code} has no associated session"
            )
            raise exceptions.EntityDoesNotExistException()

        return filtered_sessions[0]

    async def get_session_by_callback_id(
        self, callback_id: str
    ) -> schemas.AuthnSession:

        filtered_sessions: typing.List[schemas.AuthnSession] = list(
            filter(
                lambda session: session.callback_id == callback_id,
                self._sessions.values(),
            )
        )
        if len(filtered_sessions) != 1:
            logger.info(f"The callback ID: {callback_id} has no associated session")
            raise exceptions.EntityDoesNotExistException()

        return filtered_sessions[0]

    async def get_token_session_by_id(self, token_id: str) -> schemas.TokenSession:
        session: schemas.TokenSession | None = self._token_sessions.get(token_id, None)
        if session is None:
            logger.info(f"The token ID: {token_id} has no associated session")
            raise exceptions.EntityDoesNotExistException()
        return session

    async def get_token_session_by_refresh_token(
        self, refresh_token: str
    ) -> schemas.TokenSession:
        filtered_token_sessions: typing.List[schemas.TokenSession] = list(
            filter(
                lambda session: session.refresh_token == refresh_token,
                self._token_sessions.values(),
            )
        )
        if len(filtered_token_sessions) != 1:
            logger.info(f"The refresh token: {refresh_token} has no associated session")
            raise exceptions.EntityDoesNotExistException()

        return filtered_token_sessions[0]

    async def delete_session(self, session_id: str) -> None:
        self._sessions.pop(session_id)
