from auth_server.utils import constants
from . import constants

######################################## Exceptions ########################################

#################### OAuth Exceptions ####################


class AuthnException(Exception):
    def __init__(self, error: constants.ErrorCode, error_description: str) -> None:
        self.error = error
        self.error_description = error_description
        super().__init__(error_description)


class JsonResponseException(AuthnException):
    pass


class RedirectResponseException(AuthnException):
    def __init__(
        self, error: constants.ErrorCode, error_description: str, redirect_uri: str
    ) -> None:
        self.redirect_uri = redirect_uri
        super().__init__(error, error_description)


#################### Management Exceptions ####################


class EntityAlreadyExistsException(Exception):
    pass


class EntityDoesNotExistException(Exception):
    pass
