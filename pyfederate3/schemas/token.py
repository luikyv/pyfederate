from typing import Any, Dict, List
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pydantic import BaseModel, Field
import jwt

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
