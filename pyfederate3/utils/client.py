from abc import ABC, abstractmethod
from typing import List

from ..schemas.client import ClientInfo, ClientAuthnContext
from ..utils.tools import hash_secret
from .token import TokenModel


class ClientAuthenticator(ABC):
    @abstractmethod
    def is_authenticated(self, authn_context: ClientAuthnContext) -> bool:
        ...


class NoneAuthenticator(ClientAuthenticator):
    def is_authenticated(self, authn_context: ClientAuthnContext) -> bool:
        if authn_context.secret:
            return False

        return True


class SecretAuthenticator(ClientAuthenticator):
    def __init__(self, hashed_secret: str) -> None:
        self._hashed_secret = hashed_secret

    def is_authenticated(self, authn_context: ClientAuthnContext) -> bool:
        if not authn_context.secret:
            return False

        return hash_secret(authn_context.secret) == self._hashed_secret


class Client:
    def __init__(
        self,
        info: ClientInfo,
        authenticator: ClientAuthenticator,
    ) -> None:
        self._info = info
        self._authenticator = authenticator

    def get_id(self) -> str:
        return self._info.client_id

    def get_default_token_model_id(self) -> str:
        return self._info.default_token_model_id

    def get_available_scopes(self) -> List[str]:
        return self._info.scopes

    def is_authenticated(self, authn_context: ClientAuthnContext) -> bool:
        return self._authenticator.is_authenticated(authn_context=authn_context)

    def are_scopes_allowed(self, scopes: List[str]) -> bool:
        return scopes in self._info.scopes
