from pydantic import BaseModel, Field
from abc import ABC, abstractmethod


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
    def __init__(self, client_info: ClientInfo) -> None:
        self._client_info = client_info
        self._authenticator: ClientAuthenticator = client_info.authenticator

    def is_authenticated(self, authn_context: ClientAuthnContext) -> bool:
        return self._authenticator.is_authenticated(authn_context=authn_context)
