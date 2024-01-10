from pydantic import BaseModel, Field
from dataclasses import dataclass, field
from abc import ABC, abstractmethod

from ... import constants
from .. import oauth


@dataclass
class ClientAuthnInfo(ABC):
    authn_type: constants.ClientAuthnMethod

    @abstractmethod
    def is_authenticated(self, authn_context: oauth.ClientAuthnContext) -> bool:
        ...


@dataclass
class NoneAuthnInfo(ClientAuthnInfo):
    authn_type: constants.ClientAuthnMethod = field(
        init=False, default=constants.ClientAuthnMethod.NONE
    )

    @abstractmethod
    def is_authenticated(self, authn_context: oauth.ClientAuthnContext) -> bool:
        raise NotImplementedError()


@dataclass
class SecretAuthnInfo(ClientAuthnInfo):
    authn_type: constants.ClientAuthnMethod = field(
        init=False, default=constants.ClientAuthnMethod.CLIENT_SECRET_POST
    )
    hashed_secret: str

    @abstractmethod
    def is_authenticated(self, authn_context: oauth.ClientAuthnContext) -> bool:
        raise NotImplementedError()


@dataclass
class PrivateKeyJWTAuthnInfo(ClientAuthnInfo):
    authn_type: constants.ClientAuthnMethod = field(
        init=False, default=constants.ClientAuthnMethod.PRIVATE_KEY_JWT
    )
    public_key: str
    signing_alg: str

    @abstractmethod
    def is_authenticated(self, authn_context: oauth.ClientAuthnContext) -> bool:
        raise NotImplementedError()


#################### API Models ####################


class NoneAuthnInfoAPIIn(BaseModel):
    authn_info: constants.ClientAuthnMethod = Field(
        init_var=False, default=constants.ClientAuthnMethod.NONE
    )


class SecretAuthnInfoAPIIn(BaseModel):
    authn_info: constants.ClientAuthnMethod = Field(
        init_var=False, default=constants.ClientAuthnMethod.CLIENT_SECRET_POST
    )
    secret: str


class NoneAuthnInfoAPIOut(BaseModel):
    authn_info: constants.ClientAuthnMethod = Field(
        init_var=False, default=constants.ClientAuthnMethod.NONE
    )


class SecretAuthnInfoAPIOut(BaseModel):
    authn_info: constants.ClientAuthnMethod = Field(
        init_var=False, default=constants.ClientAuthnMethod.CLIENT_SECRET_POST
    )
    hashed_secret: str
