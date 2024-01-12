from pydantic import BaseModel, Field
from abc import ABC, abstractmethod

from ...tools import hash_secret
from ...constants import ClientAuthnMethod
from ..oauth import ClientAuthnContext


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


#################### API Models ####################


class BaseClientAuthnInfo(BaseModel):
    authn_info: ClientAuthnMethod


class ClientAuthnInfoIn(BaseClientAuthnInfo):
    secret: str | None


class ClientAuthnInfoOut(BaseClientAuthnInfo):
    hashed_secret: str | None = None
