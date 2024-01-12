from pydantic import BaseModel, Field
from dataclasses import dataclass, field
from typing import Dict, List

from ...constants import ResponseType, GrantType
from ...tools import generate_client_id
from ..token import TokenModel
from .authn import ClientAuthenticator, ClientAuthnInfoIn, ClientAuthnInfoOut
from ..oauth import ClientAuthnContext


@dataclass
class ClientInfo:
    client_id: str
    authenticator: ClientAuthenticator
    redirect_uris: List[str]
    response_types: List[ResponseType]
    grant_types: List[GrantType]
    scopes: List[str]
    is_pkce_required: bool
    token_model: TokenModel
    extra_params: Dict[str, str] = field(default_factory=dict)


class Client:
    def __init__(self, client_info: ClientInfo) -> None:
        self._client_info = client_info
        self._authenticator: ClientAuthenticator = client_info.authenticator

    def is_authenticated(self, authn_context: ClientAuthnContext) -> bool:
        return self._authenticator.is_authenticated(authn_context=authn_context)


#################### API Models ####################


class BaseClient(BaseModel):
    redirect_uris: List[str]
    response_types: List[ResponseType]
    grant_types: List[GrantType]
    scopes: List[str]
    is_pkce_required: bool
    token_model_id: str
    extra_params: Dict[str, str] = Field(default_factory=dict)


class ClientIn(BaseClient):
    client_id: str = Field(default_factory=generate_client_id)
    authn_info: ClientAuthnInfoIn


class ClientOut(BaseClient):
    client_id: str
    authn_info: ClientAuthnInfoOut
