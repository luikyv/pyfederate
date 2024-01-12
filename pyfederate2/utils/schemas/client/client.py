from pydantic import BaseModel, Field
from dataclasses import dataclass, field
from typing import Dict, List

from ...constants import ResponseType, GrantType
from ...tools import generate_client_id
from ..token import TokenModel
from .authn import ClientAuthenticator, ClientAuthnInfoAPIIn, ClientAuthnInfoAPIOut


@dataclass
class Client:
    client_id: str
    authenticator: ClientAuthenticator
    redirect_uris: List[str]
    response_types: List[ResponseType]
    grant_types: List[GrantType]
    scopes: List[str]
    is_pkce_required: bool
    token_model: TokenModel
    extra_params: Dict[str, str] = field(default_factory=dict)

    def to_output(self) -> "ClientAPIOut":
        raise NotImplementedError()


#################### API Models ####################


class BaseClientAPI(BaseModel):
    redirect_uris: List[str]
    response_types: List[ResponseType]
    grant_types: List[GrantType]
    scopes: List[str]
    is_pkce_required: bool
    token_model_id: str
    extra_params: Dict[str, str] = Field(default_factory=dict)


class ClientAPIIn(BaseClientAPI):
    client_id: str | None = Field(default_factory=generate_client_id)
    authn_info: ClientAuthnInfoAPIIn

    def to_client(self) -> Client:
        raise NotImplementedError()


class ClientAPIOut(BaseClientAPI):
    client_id: str
    authn_info: ClientAuthnInfoAPIOut
