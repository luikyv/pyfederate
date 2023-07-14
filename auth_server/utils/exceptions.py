from . import constants

class HTTPException(Exception):
    
    def __init__(
        self,
        status_code: int,
        error: constants.ErrorCode,
        error_description: str,
    ) -> None:
        
        self.status_code = status_code
        self.error = error
        self.error_description = error_description
    
    def __repr__(self) -> str:
        class_name = self.__class__.__name__
        return f"{class_name}(status_code={self.status_code!r}, error={self.error.value} error_description={self.error_description!r})"

class TokenModelAlreadyExists(Exception):
    pass

class TokenModelDoesNotExist(Exception):
    pass

class ScopeAlreadyExists(Exception):
    pass

class ScopeDoesNotExist(Exception):
    pass

class ClientAlreadyExists(Exception):
    pass

class ClientDoesNotExist(Exception):
    pass

class SessionInfoAlreadyExists(Exception):
    pass

class SessionInfoDoesNotExist(Exception):
    pass