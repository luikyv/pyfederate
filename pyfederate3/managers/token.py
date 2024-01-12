from typing import List
from abc import ABC, abstractmethod

from ..schemas.token import TokenModelIn, TokenModelOut


class TokenModelManager(ABC):
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
