from pydantic import BaseModel, Field
from dataclasses import dataclass, field
from abc import ABC, abstractmethod
from typing import Dict, List

from .. import constants
from . import oauth, token_model

######################################## Client Authentication ########################################


@dataclass
class ClientAuthnInfo(ABC):
    authn_type: constants.ClientAuthnMethod

    @abstractmethod
    def authenticate(self, authn_context: oauth.ClientAuthnContext) -> None:
        ...


@dataclass
class NoneAuthnInfo(ClientAuthnInfo):
    authn_type: constants.ClientAuthnMethod = field(
        init=False, default=constants.ClientAuthnMethod.NONE
    )

    @abstractmethod
    def authenticate(self, authn_context: oauth.ClientAuthnContext) -> None:
        raise NotImplementedError()


@dataclass
class SecretAuthnInfo(ClientAuthnInfo):
    authn_type: constants.ClientAuthnMethod = field(
        init=False, default=constants.ClientAuthnMethod.CLIENT_SECRET_POST
    )
    hashed_secret: str

    @abstractmethod
    def authenticate(self, authn_context: oauth.ClientAuthnContext) -> None:
        raise NotImplementedError()


@dataclass
class PrivateKeyJWTAuthnInfo(ClientAuthnInfo):
    authn_type: constants.ClientAuthnMethod = field(
        init=False, default=constants.ClientAuthnMethod.PRIVATE_KEY_JWT
    )
    public_key: str
    signing_alg: str

    @abstractmethod
    def authenticate(self, authn_context: oauth.ClientAuthnContext) -> None:
        raise NotImplementedError()


#################### API Models ####################


class NoneAuthnInfoIn(BaseModel):
    authn_info: constants.ClientAuthnMethod = Field(
        init_var=False, default=constants.ClientAuthnMethod.NONE
    )


class SecretAuthnInfoIn(BaseModel):
    authn_info: constants.ClientAuthnMethod = Field(
        init_var=False, default=constants.ClientAuthnMethod.CLIENT_SECRET_POST
    )
    secret: str


class NoneAuthnInfoOut(BaseModel):
    authn_info: constants.ClientAuthnMethod = Field(
        init_var=False, default=constants.ClientAuthnMethod.NONE
    )


class SecretAuthnInfoOut(BaseModel):
    authn_info: constants.ClientAuthnMethod = Field(
        init_var=False, default=constants.ClientAuthnMethod.CLIENT_SECRET_POST
    )
    hashed_secret: str


######################################## Client ########################################


@dataclass
class Client:
    client_id: str
    authn_method: ClientAuthnInfo
    redirect_uris: List[str]
    response_types: List[constants.ResponseType]
    grant_types: List[constants.GrantType]
    scopes: List[str]
    is_pkce_required: bool
    token_model: token_model.TokenModel
    extra_params: Dict[str, str] = field(default_factory=dict)

    def authenticate(self, authn_context: oauth.ClientAuthnContext) -> None:
        self.authn_method.authenticate(authn_context=authn_context)


#################### API Models ####################


class BaseClient(BaseModel):
    authn_method: ClientAuthnInfo
    redirect_uris: List[str]
    response_types: List[constants.ResponseType]
    grant_types: List[constants.GrantType]
    scopes: List[str]
    is_pkce_required: bool
    token_model_id: str
    extra_params: Dict[str, str] = Field(default_factory=dict)


class ClientIn(BaseClient):
    client_id: str | None
    authn_info: NoneAuthnInfoIn | SecretAuthnInfoIn


class ClientOut(BaseClient):
    client_id: str
    authn_info: NoneAuthnInfoOut | SecretAuthnInfoOut
