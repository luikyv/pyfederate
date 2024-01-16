from abc import ABC, abstractmethod
import jwt

from ..schemas.token import JWTTokenModelInfo, TokenInfo, Token
from ..schemas.auth import AuthnInfo
from ..utils.constants import TokenClaim
from ..utils.tools import generate_uuid, get_timestamp_now


class TokenModel(ABC):
    @abstractmethod
    def generate_token(self, authn_info: AuthnInfo) -> Token:
        ...


class JWTTokenModel(TokenModel):
    def __init__(self, jwt_model_info: JWTTokenModelInfo) -> None:
        self._model_info = jwt_model_info

    def generate_token(self, authn_info: AuthnInfo) -> Token:

        time_now: int = get_timestamp_now()
        token_info = TokenInfo(
            id=generate_uuid(),
            subject=authn_info.subject,
            issuer=self._model_info.issuer,
            issued_at=time_now,
            expiration=time_now + self._model_info.expires_in,
            client_id=authn_info.client_id,
            scopes=authn_info.scopes,
            token_model_id=self._model_info.id,
            additional_info=authn_info.additional_info,
        )
        return Token(token=self._generate_jwt(token_info=token_info), info=token_info)

    def _generate_jwt(self, token_info: TokenInfo) -> str:
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
        payload = payload | token_info.additional_info

        return jwt.encode(
            payload=payload,
            key=self._model_info.key,
            algorithm=self._model_info.signing_algorithm.value,
        )
