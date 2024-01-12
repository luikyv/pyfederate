from typing import Any, Dict, List
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pydantic import BaseModel
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


#################### API Models ####################


class BaseTokenModelAPI(BaseModel):
    id: str
    model_type: TokenModelType
    issuer: str
    expires_in: int
    is_refreshable: bool
    refresh_lifetime_secs: int
    key_id: JWK_IDS_LITERAL | None


class TokenModelAPIIn(BaseTokenModelAPI):
    def to_token_model(self) -> TokenModel:
        raise NotImplementedError()


class TokenModelAPIOut(BaseTokenModelAPI):
    pass
