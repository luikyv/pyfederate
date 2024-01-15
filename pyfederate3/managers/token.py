from typing import Dict, List
from abc import ABC, abstractmethod

from ..schemas.token import TokenModelIn, TokenModelOut, JWTTokenModelInfo
from ..schemas.oauth import JWKInfo
from ..utils.token import TokenModel, JWTTokenModel
from ..utils.telemetry import get_logger
from ..utils.tools import remove_oldest_item, get_jwk
from ..utils.constants import TokenModelType
from .exceptions import EntityAlreadyExistsException, EntityDoesNotExistException

logger = get_logger(__name__)


class InternalTokenModelManager(ABC):
    @abstractmethod
    async def get_token_model(self, token_model_id: str) -> TokenModel:
        """
        Throws:
            EntityDoesNotExist
        """
        pass


class APITokenModelManager(ABC):
    @abstractmethod
    async def create_token_model(self, token_model: TokenModelIn) -> None:
        """
        Throws:
            EntityAlreadyExists
        """
        pass

    @abstractmethod
    async def update_token_model(
        self, token_model_id: str, token_model: TokenModelIn
    ) -> None:
        """
        Throws:
            EntityAlreadyExists
        """
        pass

    @abstractmethod
    async def get_token_model_out(self, token_model_id: str) -> TokenModelOut:
        """
        Throws:
            EntityDoesNotExist
        """
        pass

    @abstractmethod
    async def get_token_models_out(self) -> List[TokenModelOut]:
        pass

    @abstractmethod
    async def delete_token_model(self, token_model_id: str) -> None:
        pass


class InMemoryTokenModelManager(APITokenModelManager, InternalTokenModelManager):
    def __init__(self, max_number: int = 10) -> None:
        self._max_number = max_number
        self._token_models: Dict[str, TokenModelIn] = {}

    async def create_token_model(self, token_model: TokenModelIn) -> None:
        if token_model.id in self._token_models:
            logger.info(f"Token model with ID: {token_model.id} already exists")
            raise EntityAlreadyExistsException()
        if len(self._token_models) >= self._max_number:
            remove_oldest_item(self._token_models)

        self._token_models[token_model.id] = token_model

    async def update_token_model(self, token_model: TokenModelIn) -> None:
        if token_model.id not in self._token_models:
            logger.info(f"Token model with ID: {token_model.id} does not exist")
            raise EntityDoesNotExistException()

        self._token_models[token_model.id] = token_model

    async def get_token_model(self, token_model_id: str) -> TokenModel:
        """
        Throws:
            EntityDoesNotExist
        """

        token_model_in: TokenModelIn | None = self._token_models.get(
            token_model_id, None
        )
        if not token_model_in:
            raise EntityDoesNotExistException()

        return self._build_token_model(token_model_in=token_model_in)

    def _build_token_model(self, token_model_in: TokenModelIn) -> TokenModel:
        if token_model_in.model_type == TokenModelType.JWT:
            jwk: JWKInfo = get_jwk(key_id=token_model_in.key_id)  # type: ignore
            return JWTTokenModel(
                jwt_model_info=JWTTokenModelInfo(
                    id=token_model_in.id,
                    issuer=token_model_in.issuer,
                    expires_in=token_model_in.expires_in,
                    is_refreshable=token_model_in.is_refreshable,
                    refresh_lifetime_secs=token_model_in.refresh_lifetime_secs,
                    key_id=jwk.key_id,
                    key=jwk.key,
                    signing_algorithm=jwk.signing_algorithm,
                )
            )

        raise RuntimeError("Invalid token model type")

    async def get_token_model_out(self, token_model_id: str) -> TokenModelOut:

        if token_model_id not in self._token_models:
            logger.info(f"Token model with ID: {token_model_id} does not exist")
            raise EntityDoesNotExistException()

        token_model: TokenModelIn = self._token_models[token_model_id]
        return TokenModelOut(**token_model.model_dump())

    async def get_token_models(self) -> List[TokenModelOut]:
        return [
            TokenModelOut(**token_model.model_dump())
            for token_model in self._token_models.values()
        ]

    async def delete_token_model(self, token_model_id: str) -> None:
        self._token_models.pop(token_model_id)
