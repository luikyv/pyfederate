from typing import Any, Dict, List
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pydantic import BaseModel, Field
import jwt

from ..constants import TokenClaim, TokenModelType, SigningAlgorithm, JWK_IDS_LITERAL
from ..tools import generate_uuid


@dataclass
class TokenInfo:
    subject: str
    issuer: str
    issued_at: int
    expiration: int
    client_id: str
    scopes: List[str]
    id: str = field(default_factory=generate_uuid)
    additional_info: Dict[str, str] = field(default_factory=dict)


@dataclass
class TokenModelInfo(ABC):
    id: str
    issuer: str
    expires_in: int
    is_refreshable: bool
    refresh_lifetime_secs: int


class TokenModel(ABC):
    @abstractmethod
    def generate_token(self, token_info: TokenInfo) -> str:
        ...


@dataclass
class JWTTokenModelInfo(TokenModelInfo):
    key_id: str
    key: str
    signing_algorithm: SigningAlgorithm


class JWTTokenModel(TokenModel):
    def __init__(self, jwt_model_info: JWTTokenModelInfo) -> None:
        self._model_info = jwt_model_info

    def generate_token(self, token_info: TokenInfo) -> str:

        return jwt.encode(
            payload=self._to_jwt_payload(token_info=token_info),
            key=self._model_info.key,
            algorithm=self._model_info.signing_algorithm.value,
        )

    def _to_jwt_payload(self, token_info: TokenInfo) -> Dict[str, Any]:
        payload = {
            TokenClaim.JWT_ID.value: token_info.id,
            TokenClaim.SUBJECT.value: token_info.subject,
            TokenClaim.ISSUER.value: token_info.issuer,
            TokenClaim.ISSUED_AT.value: token_info.issued_at,
            TokenClaim.EXPIRATION.value: token_info.expiration,
            TokenClaim.CLIENT_ID.value: token_info.client_id,
            TokenClaim.SCOPE.value: " ".join(token_info.scopes),
        }

        # Merge the two dicts and allow the additional_info to override values in the payload
        return payload | token_info.additional_info


#################### API Models ####################


class BaseTokenModel(BaseModel):
    id: str
    model_type: TokenModelType
    issuer: str
    expires_in: int
    is_refreshable: bool = Field(default=False)
    refresh_lifetime_secs: int = Field(default=0)
    key_id: JWK_IDS_LITERAL | None


class TokenModelIn(BaseTokenModel):
    pass


class TokenModelOut(BaseTokenModel):
    pass
