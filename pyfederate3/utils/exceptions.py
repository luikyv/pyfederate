from ..utils.constants import ErrorCode


class OAuthnException(Exception):
    def __init__(self, error: ErrorCode, error_description: str) -> None:
        self.error = error
        self.error_description = error_description
        super().__init__(error_description)


class OAuthJsonResponseException(OAuthnException):
    pass


class OAuthRedirectResponseException(OAuthnException):
    def __init__(
        self,
        error: ErrorCode,
        error_description: str,
        redirect_uri: str,
        state: str | None,
    ) -> None:
        self.redirect_uri = redirect_uri
        self.state = state
        super().__init__(error=error, error_description=error_description)
