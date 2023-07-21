import typing
from abc import ABC, abstractmethod
from sqlalchemy import delete, Engine
from sqlalchemy.orm import Session

from .. import schemas, models, constants, telemetry, exceptions

logger = telemetry.get_logger(__name__)

######################################## Interfaces ########################################


class TokenModelManager(ABC):

    @abstractmethod
    async def create_token_model(self, token_model: schemas.TokenModelUpsert) -> schemas.TokenModel:
        """
        Throws:
            exceptions.TokenModelAlreadyExists
        """
        pass

    @abstractmethod
    async def get_token_model(self, token_model_id: str) -> schemas.TokenModel:
        """
        Throws:
            exceptions.TokenModelDoesNotExist
        """
        pass

    @abstractmethod
    async def get_token_models(self) -> typing.List[schemas.TokenModel]:
        pass

    @abstractmethod
    async def get_model_key_ids(self) -> typing.List[str]:
        """Get the signing keys defined in all the existent token models
        """
        pass

    @abstractmethod
    async def delete_token_model(self, token_model_id: str) -> None:
        pass

######################################## Implementations ########################################

#################### Mock ####################


class MockedTokenModelManager(TokenModelManager):

    def __init__(self, max_number: int = 10) -> None:
        self.token_models: typing.Dict[str, schemas.TokenModel] = {}

    async def create_token_model(self, token_model: schemas.TokenModelUpsert) -> schemas.TokenModel:
        if (token_model.id in self.token_models):
            logger.info(
                f"Token model with ID: {token_model.id} already exists")
            raise exceptions.TokenModelAlreadyExists()

        if token_model.token_type == constants.TokenType.JWT:
            self.token_models[token_model.id] = schemas.JWTTokenModel(
                id=token_model.id,
                issuer=token_model.issuer,
                expires_in=token_model.expires_in,
                key_id=token_model.key_id,  # type: ignore
                key=constants.PRIVATE_JWKS[
                    token_model.key_id].key,  # type: ignore
                signing_algorithm=constants.PRIVATE_JWKS[
                    token_model.key_id].signing_algorithm,  # type: ignore
            )

        return self.token_models[token_model.id]

    async def get_token_model(self, token_model_id: str) -> schemas.TokenModel:

        if (token_model_id not in self.token_models):
            logger.info(
                f"Token model with ID: {token_model_id} does not exist")
            raise exceptions.TokenModelDoesNotExist()

        return self.token_models[token_model_id]

    async def get_token_models(self) -> typing.List[schemas.TokenModel]:
        return list(self.token_models.values())

    async def get_model_key_ids(self) -> typing.List[str]:
        return [token_model.key_id for token_model in self.token_models if isinstance(token_model, schemas.JWTTokenModel)]

    async def delete_token_model(self, token_model_id: str) -> None:
        self.token_models.pop(token_model_id)

#################### OLTP ####################


class OLTPTokenModelManager(TokenModelManager):

    def __init__(self, engine: Engine) -> None:
        self.engine = engine

    async def create_token_model(self, token_model: schemas.TokenModelUpsert) -> schemas.TokenModel:

        token_model_db = models.TokenModel.to_db_model(token_model=token_model)
        with Session(self.engine) as db:
            db.add(token_model_db)
            db.commit()
            return token_model_db.to_schema()

    async def get_token_model(self, token_model_id: str) -> schemas.TokenModel:

        with Session(self.engine) as db:
            token_model_db = db.query(models.TokenModel).filter(
                models.TokenModel.id == token_model_id).first()

        if (token_model_db is None):
            raise exceptions.TokenModelDoesNotExist()

        return token_model_db.to_schema()

    async def get_token_models(self) -> typing.List[schemas.TokenModel]:

        with Session(self.engine) as db:
            token_models_db: typing.List[models.TokenModel] = db.query(
                models.TokenModel).all()
        return [token_model.to_schema() for token_model in token_models_db]

    async def get_model_key_ids(self) -> typing.List[str]:
        with Session(self.engine) as db:
            token_models_db: typing.List[models.TokenModel] = db.query(
                models.TokenModel).all()

        return [token_model_db.key_id for token_model_db in token_models_db if token_model_db.key_id]

    async def delete_token_model(self, token_model_id: str) -> None:
        with Session(self.engine) as db:
            delete(models.TokenModel).where(
                models.TokenModel.id == token_model_id)
            db.commit()
