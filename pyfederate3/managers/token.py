from typing import Dict, List
from abc import ABC, abstractmethod

from ..schemas.token import TokenModelIn, TokenModelOut
from ..utils.token import TokenModel
from ..utils.telemetry import get_logger
from ..utils.tools import remove_oldest_item
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
        raise NotImplementedError()

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
