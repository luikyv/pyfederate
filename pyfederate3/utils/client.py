from abc import ABC, abstractmethod

from ..schemas.client import ClientInfo, ClientAuthnContext
from .token import TokenModel


class ClientAuthenticator(ABC):
    @abstractmethod
    def is_authenticated(self, authn_context: ClientAuthnContext) -> bool:
        ...


class NoneAuthenticator(ClientAuthenticator):
    def is_authenticated(self, authn_context: ClientAuthnContext) -> bool:
        raise NotImplementedError()


class SecretAuthenticator(ClientAuthenticator):
    def __init__(self, hashed_secret: str) -> None:
        self._hashed_secret = hashed_secret

    def is_authenticated(self, authn_context: ClientAuthnContext) -> bool:
        raise NotImplementedError()


class Client:
    def __init__(
        self,
        info: ClientInfo,
        authenticator: ClientAuthenticator,
        token_model: TokenModel,
    ) -> None:
        self._info = info
        self._authenticator = authenticator
        self._token_model = token_model
