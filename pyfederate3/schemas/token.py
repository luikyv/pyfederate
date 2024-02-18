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


@dataclass(kw_only=True)
class TokenContextInfo:
    subject: str
    client_id: str
    scopes: List[str]
    additional_info: Dict[str, str] = field(default_factory=dict)


@dataclass
class TokenInfo(TokenContextInfo):
    id: str
    issuer: str
    issued_at: int
    expires_in_secs: int
    token_model_id: str


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
    token_model_type: TokenModelType
    issuer: str
    expires_in: int
    is_refreshable: bool = Field(default=False)
    refresh_lifetime_secs: int = Field(default=0)
    key_id: str | None


class TokenModelIn(BaseTokenModel):
    pass


class TokenModelOut(BaseTokenModel):
    pass
