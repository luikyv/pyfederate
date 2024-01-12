from typing import List
from abc import ABC, abstractmethod

from ..schemas.token import TokenModel


class TokenModelManager(ABC):
    @abstractmethod
    async def create_token_model(self, token_model: TokenModel) -> None:
        """
        Throws:
            EntityAlreadyExists
        """
        pass

    @abstractmethod
    async def update_token_model(
        self, token_model_id: str, token_model: TokenModel
    ) -> None:
        """
        Throws:
            EntityAlreadyExists
        """
        pass

    @abstractmethod
    async def get_token_model(self, token_model_id: str) -> TokenModel:
        """
        Throws:
            EntityDoesNotExist
        """
        pass

    @abstractmethod
    async def get_token_models(self) -> List[TokenModel]:
        pass

    # @abstractmethod
    # async def get_model_key_ids(self) -> List[str]:
    #     """Get the signing keys defined in all the existent token models"""
    #     pass

    @abstractmethod
    async def delete_token_model(self, token_model_id: str) -> None:
        pass
