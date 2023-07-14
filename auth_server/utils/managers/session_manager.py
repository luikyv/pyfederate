import typing
from abc import ABC, abstractmethod

from .. import schemas, telemetry
from .. import exceptions

logger = telemetry.get_logger(__name__)

######################################## Interfaces ########################################

class SessionManager(ABC):

    @abstractmethod
    async def create_session(self, session_info: schemas.SessionInfo) -> None:
        """
        Throws:
            exceptions.SessionInfoAlreadyExists
        """
        pass
    
    @abstractmethod
    async def get_session_by_auth_code(self, auth_code: str) -> schemas.SessionInfo:
        """
        Throws:
            exceptions.SessionInfoDoesNotExist
        """
        pass

    @abstractmethod
    async def get_session_by_callback_id(self, callback_id: str) -> schemas.SessionInfo:
        """
        Throws:
            exceptions.SessionInfoDoesNotExist
        """
        pass

    @abstractmethod
    async def delete_session(self, tracking_id: str) -> None:
        """
        Throws:
            exceptions.SessionInfoDoesNotExist
        """
        pass

######################################## Implementations ########################################

class MockedSessionManager(SessionManager):

    def __init__(self) -> None:
        self.sessions: typing.Dict[str, schemas.SessionInfo] = {}
    
    async def create_session(self, session_info: schemas.SessionInfo) -> None:

        if(session_info.tracking_id in self.sessions):
            logger.info(f"The tracking ID: {session_info.tracking_id} has already an associated session")
            raise exceptions.ScopeAlreadyExists()
        
        self.sessions[session_info.tracking_id] = session_info
    
    async def get_session_by_auth_code(self, auth_code: str) -> schemas.SessionInfo:
        filtered_sessions: typing.List[schemas.SessionInfo] = list(filter(
            lambda session_info: session_info.auth_code == auth_code, self.sessions.values()
        ))
        if(len(filtered_sessions) != 1):
            logger.info(f"The authorization code: {auth_code} has no associated session")
            raise exceptions.SessionInfoDoesNotExist()
        
        return filtered_sessions[0]
    
    async def get_session_by_callback_id(self, callback_id: str) -> schemas.SessionInfo:
        
        filtered_sessions: typing.List[schemas.SessionInfo] = list(filter(
            lambda session_info: session_info.callback_id == callback_id, self.sessions.values()
        ))
        if(len(filtered_sessions) != 1):
            logger.info(f"The callback ID: {callback_id} has no associated session")
            raise exceptions.SessionInfoDoesNotExist()
        
        return filtered_sessions[0]

    async def delete_session(self, tracking_id: str) -> None:
        self.sessions.pop(tracking_id)