from abc import ABC, abstractmethod
import jwt

from ..schemas.token import JWTTokenModelInfo, TokenInfo, Token
from ..schemas.token import TokenContextInfo
from ..utils.constants import TokenClaim
from ..utils.tools import generate_uuid, get_timestamp_now


class TokenModel(ABC):
    @abstractmethod
    def generate_token(self, context: TokenContextInfo) -> Token:
        ...


class JWTTokenModel(TokenModel):
    def __init__(self, jwt_model_info: JWTTokenModelInfo) -> None:
        self._model_info = jwt_model_info

    def generate_token(self, context: TokenContextInfo) -> Token:

        token_info = TokenInfo(
            id=generate_uuid(),
            subject=context.subject,
            issuer=self._model_info.issuer,
            issued_at=get_timestamp_now(),
            expires_in_secs=self._model_info.expires_in,
            client_id=context.client_id,
            scopes=context.scopes,
            token_model_id=self._model_info.id,
            additional_info=context.additional_info,
        )
        return Token(token=self._generate_jwt(token_info=token_info), info=token_info)

    def _generate_jwt(self, token_info: TokenInfo) -> str:
        payload = {
            TokenClaim.JWT_ID.value: token_info.id,
            TokenClaim.SUBJECT.value: token_info.subject,
            TokenClaim.ISSUER.value: token_info.issuer,
            TokenClaim.ISSUED_AT.value: token_info.issued_at,
            TokenClaim.EXPIRATION.value: token_info.issued_at
            + token_info.expires_in_secs,
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
