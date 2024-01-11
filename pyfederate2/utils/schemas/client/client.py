from pydantic import BaseModel, Field
from dataclasses import dataclass, field
from typing import Dict, List

from ...constants import ResponseType, GrantType
from ..oauth import ClientAuthnContext
from ..token import TokenModel
from .authn import (
    NoneAuthnInfoAPIIn,
    SecretAuthnInfoAPIIn,
    NoneAuthnInfoAPIOut,
    SecretAuthnInfoAPIOut,
    ClientAuthnInfo,
)


@dataclass
class Client:
    client_id: str
    authn_method: ClientAuthnInfo
    redirect_uris: List[str]
    response_types: List[ResponseType]
    grant_types: List[GrantType]
    scopes: List[str]
    is_pkce_required: bool
    token_model: TokenModel
    extra_params: Dict[str, str] = field(default_factory=dict)

    def is_authenticated(self, authn_context: ClientAuthnContext) -> bool:
        return self.authn_method.is_authenticated(authn_context=authn_context)

    def to_output(self) -> "ClientAPIOut":
        raise NotImplementedError()


class BaseClientAPI(BaseModel):
    authn_method: ClientAuthnInfo
    redirect_uris: List[str]
    response_types: List[ResponseType]
    grant_types: List[GrantType]
    scopes: List[str]
    is_pkce_required: bool
    token_model_id: str
    extra_params: Dict[str, str] = Field(default_factory=dict)


class ClientAPIIn(BaseClientAPI):
    client_id: str | None
    authn_info: NoneAuthnInfoAPIIn | SecretAuthnInfoAPIIn

    def to_client(self) -> Client:
        raise NotImplementedError()


class ClientAPIOut(BaseClientAPI):
    client_id: str
    authn_info: NoneAuthnInfoAPIOut | SecretAuthnInfoAPIOut
