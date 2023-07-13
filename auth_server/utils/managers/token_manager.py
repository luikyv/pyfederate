import typing
from dataclasses import asdict
from abc import ABC, abstractmethod
from sqlalchemy import delete, Engine
from sqlalchemy.orm import Session

from .. import schemas, models, exceptions

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

class OLTPTokenModelManager(TokenModelManager):

    def __init__(self, engine: Engine) -> None:
        self.engine = engine
    
    async def create_token_model(self, token_model: schemas.TokenModelUpsert) -> schemas.TokenModel:
        with Session(self.engine) as db:
            
            token_model_db = models.TokenModel(**token_model.to_db_dict())
            db.add(token_model_db)
            db.commit()
        
            return token_model_db.to_schema()

    async def get_token_model(self, token_model_id: str) -> schemas.TokenModel:

        with Session(self.engine) as db:
            token_model_db = db.query(models.TokenModel).filter(models.TokenModel.id == token_model_id).first()
        
        if(token_model_db is None):
            raise exceptions.TokenModelDoesNotExist()
        
        return token_model_db.to_schema()
    
    async def get_token_models(self) -> typing.List[schemas.TokenModel]:

        with Session(self.engine) as db:
            token_models_db: typing.List[models.TokenModel] = db.query(models.TokenModel).all()
        return [token_model.to_schema() for token_model in token_models_db]
    
    async def get_model_key_ids(self) -> typing.List[str]:
        with Session(self.engine) as db:
            token_models_db: typing.List[models.TokenModel] = db.query(models.TokenModel).all()

        return [token_model_db.key_id for token_model_db in token_models_db if token_model_db.key_id]

    async def delete_token_model(self, token_model_id: str) -> None:
        with Session(self.engine) as db:
            delete(models.TokenModel).where(models.TokenModel.id == token_model_id)
            db.commit()
    
    
