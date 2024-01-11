from typing import Any, Dict, List
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pydantic import BaseModel
import jwt

from ..constants import TokenClaim, SigningAlgorithm, JWK_IDS_LITERAL
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

    def to_jwt_payload(self) -> Dict[str, Any]:
        payload = {
            TokenClaim.JWT_ID.value: self.id,
            TokenClaim.SUBJECT.value: self.subject,
            TokenClaim.ISSUER.value: self.issuer,
            TokenClaim.ISSUED_AT.value: self.issued_at,
            TokenClaim.EXPIRATION.value: self.expiration,
            TokenClaim.CLIENT_ID.value: self.client_id,
            TokenClaim.SCOPE.value: " ".join(self.scopes),
        }

        # Merge the two dicts and allow the additional_info to override values in the payload
        return payload | self.additional_info


@dataclass
class TokenModel(ABC):
    id: str
    issuer: str
    expires_in: int
    is_refreshable: bool
    refresh_lifetime_secs: int

    @abstractmethod
    def generate_token(self, token_info: TokenInfo) -> str:
        ...

    @abstractmethod
    def to_output(self) -> "TokenModelAPIOut":
        ...


@dataclass
class JWTTokenModel(TokenModel):
    key_id: str
    key: str
    signing_algorithm: SigningAlgorithm

    def generate_token(self, token_info: TokenInfo) -> str:

        return jwt.encode(
            payload=token_info.to_jwt_payload(),
            key=self.key,
            algorithm=self.signing_algorithm.value,
        )

    def to_output(self) -> "TokenModelAPIOut":
        raise NotImplementedError()


class BaseTokenModelAPI(BaseModel):
    id: str
    issuer: str
    expires_in: int
    is_refreshable: bool
    refresh_lifetime_secs: int


class TokenModelAPIIn(BaseModel, ABC):
    @abstractmethod
    def to_token_model(self) -> TokenModel:
        raise NotImplementedError()


class TokenModelAPIOut(BaseModel):
    pass


class JWTBaseTokenModelAPI(BaseTokenModelAPI):
    key_id: str | JWK_IDS_LITERAL


class JWTTokenModelAPIIn(TokenModelAPIIn, JWTBaseTokenModelAPI):
    pass


class JWTTokenModelAPIOut(TokenModelAPIOut, JWTBaseTokenModelAPI):
    pass
