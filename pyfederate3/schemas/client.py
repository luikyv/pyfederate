from typing import Dict, List
from dataclasses import dataclass, field
from pydantic import BaseModel, Field

from ..utils.constants import ResponseType, GrantType, ClientAuthnMethod
from ..utils.tools import generate_client_id


@dataclass
class ClientInfo:
    client_id: str
    redirect_uris: List[str]
    response_types: List[ResponseType]
    grant_types: List[GrantType]
    scopes: List[str]
    pkce_is_required: bool
    default_token_model_id: str
    extra_params: Dict[str, str] = field(default_factory=dict)


@dataclass
class ClientAuthnContext:
    secret: str | None


#################### API Models ####################


class BaseClientAuthnInfo(BaseModel):
    authn_info: ClientAuthnMethod


class ClientAuthnInfoIn(BaseClientAuthnInfo):
    secret: str | None


class ClientAuthnInfoOut(BaseClientAuthnInfo):
    hashed_secret: str | None = None


class BaseClient(BaseModel):
    redirect_uris: List[str]
    response_types: List[ResponseType]
    grant_types: List[GrantType]
    scopes: List[str]
    is_pkce_required: bool
    default_token_model_id: str
    extra_params: Dict[str, str] = Field(default_factory=dict)


class ClientIn(BaseClient):
    client_id: str = Field(default_factory=generate_client_id)
    authn_info: ClientAuthnInfoIn


class ClientOut(BaseClient):
    client_id: str
    authn_info: ClientAuthnInfoOut
