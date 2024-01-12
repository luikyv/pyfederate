from abc import ABC, abstractmethod

from ..schemas.token import JWTTokenModelInfo


class TokenModel(ABC):
    @abstractmethod
    def generate_token(self) -> str:
        ...


class JWTTokenModel(TokenModel):
    def __init__(self, jwt_model_info: JWTTokenModelInfo) -> None:
        self._model_info = jwt_model_info

    def generate_token(self) -> str:

        raise NotImplementedError()
