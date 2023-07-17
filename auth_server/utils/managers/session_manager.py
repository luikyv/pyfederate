import typing
from abc import ABC, abstractmethod

from .. import schemas, telemetry
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
    async def update_session(self, session: schemas.AuthnSession) -> None:
        """
        Throws:
            exceptions.SessionInfoDoesNotExist
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
    async def get_session_by_callback_id(self, callback_id: str) -> schemas.AuthnSession:
        """
        Throws:
            exceptions.SessionInfoDoesNotExist
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

class MockedSessionManager(SessionManager):

    def __init__(self) -> None:
        self.sessions: typing.Dict[str, schemas.AuthnSession] = {}
    
    async def create_session(self, session: schemas.AuthnSession) -> None:

        if(session.id in self.sessions):
            logger.info(f"The session ID: {session.id} already exists")
            raise exceptions.SessionInfoAlreadyExists()
        
        self.sessions[session.id] = session
    
    async def update_session(self, session: schemas.AuthnSession) -> None:
        
        if(session.id not in self.sessions):
            logger.info(f"The session ID: {session.id} does not exist")
            raise exceptions.SessionInfoDoesNotExist()

        self.sessions[session.id] = session
    
    async def get_session_by_authz_code(self, authz_code: str) -> schemas.AuthnSession:
        
        filtered_sessions: typing.List[schemas.AuthnSession] = list(filter(
            lambda session: session.authz_code == authz_code, self.sessions.values()
        ))
        if(len(filtered_sessions) != 1):
            logger.info(f"The authorization code: {authz_code} has no associated session")
            raise exceptions.SessionInfoDoesNotExist()
        
        return filtered_sessions[0]
    
    async def get_session_by_callback_id(self, callback_id: str) -> schemas.AuthnSession:
        
        filtered_sessions: typing.List[schemas.AuthnSession] = list(filter(
            lambda session: session.callback_id == callback_id, self.sessions.values()
        ))
        if(len(filtered_sessions) != 1):
            logger.info(f"The callback ID: {callback_id} has no associated session")
            raise exceptions.SessionInfoDoesNotExist()
        
        return filtered_sessions[0]

    async def delete_session(self, session_id: str) -> None:
        self.sessions.pop(session_id)