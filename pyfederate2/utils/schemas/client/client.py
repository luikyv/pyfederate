from pydantic import BaseModel, Field
from dataclasses import dataclass, field
from typing import Dict, List

from ... import constants
from .. import oauth, token_model
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
    response_types: List[constants.ResponseType]
    grant_types: List[constants.GrantType]
    scopes: List[str]
    is_pkce_required: bool
    token_model: token_model.TokenModel
    extra_params: Dict[str, str] = field(default_factory=dict)

    def is_authenticated(self, authn_context: oauth.ClientAuthnContext) -> bool:
        return self.authn_method.is_authenticated(authn_context=authn_context)


class BaseClientAPI(BaseModel):
    authn_method: ClientAuthnInfo
    redirect_uris: List[str]
    response_types: List[constants.ResponseType]
    grant_types: List[constants.GrantType]
    scopes: List[str]
    is_pkce_required: bool
    token_model_id: str
    extra_params: Dict[str, str] = Field(default_factory=dict)


class ClientAPIIn(BaseClientAPI):
    client_id: str | None
    authn_info: NoneAuthnInfoAPIIn | SecretAuthnInfoAPIIn


class ClientAPIOut(BaseClientAPI):
    client_id: str
    authn_info: NoneAuthnInfoAPIOut | SecretAuthnInfoAPIOut
