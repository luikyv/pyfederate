from pydantic import BaseModel, Field
from dataclasses import dataclass, field
from abc import ABC, abstractmethod

from ...constants import ClientAuthnMethod
from ..oauth import ClientAuthnContext


@dataclass
class ClientAuthnInfo(ABC):
    authn_type: ClientAuthnMethod

    @abstractmethod
    def is_authenticated(self, authn_context: ClientAuthnContext) -> bool:
        ...


@dataclass
class NoneAuthnInfo(ClientAuthnInfo):
    authn_type: ClientAuthnMethod = field(init=False, default=ClientAuthnMethod.NONE)

    @abstractmethod
    def is_authenticated(self, authn_context: ClientAuthnContext) -> bool:
        raise NotImplementedError()


@dataclass
class SecretAuthnInfo(ClientAuthnInfo):
    authn_type: ClientAuthnMethod = field(
        init=False, default=ClientAuthnMethod.CLIENT_SECRET_POST
    )
    hashed_secret: str

    @abstractmethod
    def is_authenticated(self, authn_context: ClientAuthnContext) -> bool:
        raise NotImplementedError()


@dataclass
class PrivateKeyJWTAuthnInfo(ClientAuthnInfo):
    authn_type: ClientAuthnMethod = field(
        init=False, default=ClientAuthnMethod.PRIVATE_KEY_JWT
    )
    public_key: str
    signing_alg: str

    @abstractmethod
    def is_authenticated(self, authn_context: ClientAuthnContext) -> bool:
        raise NotImplementedError()


class NoneAuthnInfoAPIIn(BaseModel):
    authn_info: ClientAuthnMethod = Field(
        init_var=False, default=ClientAuthnMethod.NONE
    )


class NoneAuthnInfoAPIOut(BaseModel):
    authn_info: ClientAuthnMethod = Field(
        init_var=False, default=ClientAuthnMethod.NONE
    )


class SecretAuthnInfoAPIIn(BaseModel):
    authn_info: ClientAuthnMethod = Field(
        init_var=False, default=ClientAuthnMethod.CLIENT_SECRET_POST
    )
    secret: str


class SecretAuthnInfoAPIOut(BaseModel):
    authn_info: ClientAuthnMethod = Field(
        init_var=False, default=ClientAuthnMethod.CLIENT_SECRET_POST
    )
    hashed_secret: str
