from typing import List, Dict
from dataclasses import dataclass, field
from pydantic import BaseModel

from . import constants


class AuthnMethod(BaseModel):
    authn_type: constants.ClientAuthnMethod


@dataclass
class NoneAuthnMethod(AuthnMethod):
    authn_type: constants.ClientAuthnMethod = field(
        init=False, default=constants.ClientAuthnMethod.NONE
    )


@dataclass
class SecretAuthnMethod(AuthnMethod):
    authn_type: constants.ClientAuthnMethod = field(
        init=False, default=constants.ClientAuthnMethod.CLIENT_SECRET_POST
    )
    hashed_secret: str


@dataclass
class PrivateKeyJWTAuthnMethod(AuthnMethod):
    authn_type: constants.ClientAuthnMethod = field(
        init=False, default=constants.ClientAuthnMethod.PRIVATE_KEY_JWT
    )
    key: str
    signing_alg: str


@dataclass
class Client:
    id: str
    authn_method: AuthnMethod
    token_model_id: str
    redirect_uris: List[str]
    response_types: List[constants.ResponseType]
    grant_types: List[constants.GrantType]
    scopes: List[str]
    is_pkce_required: bool
    extra_params: Dict[str, str] = field(default_factory=dict)


class ClientIn(BaseModel):
    pass
