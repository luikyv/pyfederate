from typing import Optional, Dict, Any
from fastapi import HTTPException as FastAPIHTTPException

from . import constants

class HTTPException(FastAPIHTTPException):
    
    def __init__(
        self,
        status_code: int,
        error_code: constants.ErrorCode,
        detail: Any = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> None:
        super().__init__(status_code=status_code, detail=detail, headers=headers)
        self.error_code = error_code
    
    def __repr__(self) -> str:
        class_name = self.__class__.__name__
        return f"{class_name}(status_code={self.status_code!r}, error_code={self.error_code.value} detail={self.detail!r})"

class ScopeAlreadyExists(Exception):
    pass

class ScopeDoesNotExist(Exception):
    pass

class ClientAlreadyExists(Exception):
    pass

class ClientDoesNotExist(Exception):
    pass