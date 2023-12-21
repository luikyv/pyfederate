from typing import Any, Dict, List
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pydantic import BaseModel
import jwt

from .. import constants, tools

######################################## Token Model ########################################


@dataclass
class TokenInfo:
    subject: str
    issuer: str
    issued_at: int
    expiration: int
    client_id: str
    scopes: List[str]
    id: str = field(default_factory=tools.generate_uuid)
    additional_info: Dict[str, str] = field(default_factory=dict)

    def to_jwt_payload(self) -> Dict[str, Any]:
        payload = {
            constants.TokenClaim.JWT_ID.value: self.id,
            constants.TokenClaim.SUBJECT.value: self.subject,
            constants.TokenClaim.ISSUER.value: self.issuer,
            constants.TokenClaim.ISSUED_AT.value: self.issued_at,
            constants.TokenClaim.EXPIRATION.value: self.expiration,
            constants.TokenClaim.CLIENT_ID.value: self.client_id,
            constants.TokenClaim.SCOPE.value: " ".join(self.scopes),
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


class JWTTokenModel(TokenModel):
    key_id: str
    key: str
    signing_algorithm: constants.SigningAlgorithm

    def generate_token(self, token_info: TokenInfo) -> str:

        return jwt.encode(
            payload=token_info.to_jwt_payload(),
            key=self.key,
            algorithm=self.signing_algorithm.value,
        )


#################### API Models ####################


class BaseTokenModel(BaseModel):
    id: str
    issuer: str
    expires_in: int
    is_refreshable: bool
    refresh_lifetime_secs: int


class JWTBaseTokenModel(BaseTokenModel):
    key_id: str | constants.JWK_IDS_LITERAL


class JWTTokenModelIn(JWTBaseTokenModel):
    pass


class JWTTokenModelOut(JWTBaseTokenModel):
    pass
