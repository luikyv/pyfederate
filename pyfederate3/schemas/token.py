from typing import Dict, List
from dataclasses import dataclass, field
from pydantic import BaseModel, Field

from ..utils.constants import SigningAlgorithm, TokenModelType


@dataclass
class TokenModelInfo:
    id: str
    issuer: str
    expires_in: int
    is_refreshable: bool
    refresh_lifetime_secs: int


@dataclass
class JWTTokenModelInfo(TokenModelInfo):
    key_id: str
    key: str
    signing_algorithm: SigningAlgorithm


@dataclass
class TokenInfo:
    id: str
    subject: str
    issuer: str
    issued_at: int
    expiration: int
    client_id: str
    scopes: List[str]
    token_model_id: str
    additional_info: Dict[str, str] = field(default_factory=dict)


@dataclass
class Token:
    token: str
    info: TokenInfo


@dataclass
class JWKInfo:
    key_id: str
    key: str
    signing_algorithm: SigningAlgorithm


#################### API Models ####################


class BaseTokenModel(BaseModel):
    id: str
    model_type: TokenModelType
    issuer: str
    expires_in: int
    is_refreshable: bool = Field(default=False)
    refresh_lifetime_secs: int = Field(default=0)
    key_id: str | None


class TokenModelIn(BaseTokenModel):
    pass


class TokenModelOut(BaseTokenModel):
    pass
