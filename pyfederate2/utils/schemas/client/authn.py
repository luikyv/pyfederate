from pydantic import BaseModel, Field
from abc import ABC, abstractmethod

from ...constants import ClientAuthnMethod
from ..oauth import ClientAuthnContext


class ClientAuthenticator(ABC):
    @abstractmethod
    def is_authenticated(self, authn_context: ClientAuthnContext) -> bool:
        ...


class NoneAuthenticator(ClientAuthenticator):
    def is_authenticated(self, authn_context: ClientAuthnContext) -> bool:
        raise NotImplementedError()


class SecretAuthnAuthenticator(ClientAuthenticator):
    def __init__(self, hashed_secret: str) -> None:
        self._hashed_secret = hashed_secret

    def is_authenticated(self, authn_context: ClientAuthnContext) -> bool:
        raise NotImplementedError()


#################### API Models ####################


class BaseClientAuthnInfo(BaseModel):
    authn_info: ClientAuthnMethod


class ClientAuthnInfoAPIIn(BaseClientAuthnInfo):
    secret: str | None


class ClientAuthnInfoAPIOut(BaseClientAuthnInfo):
    hashed_secret: str | None
