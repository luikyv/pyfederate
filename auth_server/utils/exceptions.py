from . import constants


# class HTTPException(Exception):

#     def __init__(
#         self,
#         status_code: int,
#         error: constants.ErrorCode,
#         error_description: str,
#     ) -> None:

#         self.status_code = status_code
#         self.error = error
#         self.error_description = error_description

#     def __repr__(self) -> str:
#         class_name = self.__class__.__name__
#         return f"{class_name}(status_code={self.status_code!r}, error={self.error.value} error_description={self.error_description!r})"


class CustomException(Exception):
    def __init__(self, message: str | None = None) -> None:
        self.message = message
        if message:
            super().__init__(message)


class TokenModelAlreadyExistsException(CustomException):
    pass


class TokenModelDoesNotExistException(CustomException):
    pass


class ScopeAlreadyExistsException(CustomException):
    pass


class ScopeDoesNotExistException(CustomException):
    pass


class ClientAlreadyExistsException(CustomException):
    pass


class ClientDoesNotExistException(CustomException):
    pass


class SessionInfoAlreadyExistsException(CustomException):
    pass


class SessionInfoDoesNotExistException(CustomException):
    pass


class AuthnStepAlreadyExistsException(CustomException):
    pass


class NoAuthenticationPoliciesAvailableException(CustomException):
    pass


class AuthnPolicyAlreadyExistsException(CustomException):
    pass


class PolicyFinishedWithoudMappingTheUserIDException(CustomException):
    pass


class InvalidGrantTypeException(CustomException):
    pass


class ClientIsNotAuthenticatedException(CustomException):
    pass


class RequestedScopesAreNotAllowedException(CustomException):
    pass


class ResponseTypeIsNotAllowedException(CustomException):
    pass


class PCKEIsRequiredException(CustomException):
    pass


class ParameterNotAllowedException(CustomException):
    pass


class InvalidAuthorizationCodeException(CustomException):
    pass


class InvalidClientIDException(CustomException):
    pass


class InvalidRedirectURIException(CustomException):
    pass


class UnknownUserKeyException(CustomException):
    pass


class InvalidPCKEException(CustomException):
    pass


class GrantTypeNotAllowedException(CustomException):
    pass


class JWTModelMustHaveKeyIDException(CustomException):
    pass


class AuthzCodeAlreadyIssuedException(CustomException):
    """The authorization code was already issue for a given callback id"""
