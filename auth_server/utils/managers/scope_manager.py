from dataclasses import asdict
import typing
from sqlalchemy import delete, Engine
from sqlalchemy.orm import Session
from abc import ABC, abstractmethod

from .. import schemas, models, exceptions

######################################## Interfaces ########################################

class ScopeManager(ABC):

    @abstractmethod
    async def create_scope(self, scope: schemas.ScopeUpsert) -> None:
        """
        Throws:
            exceptions.ScopeAlreadyExists
        """
        pass

    @abstractmethod
    async def update_scope(self, scope: schemas.ScopeUpsert) -> None:
        """
        Throws:
            exceptions.ScopeDoesNotExist
        """
        pass
    
    @abstractmethod
    async def get_scope(self, scope_name: str) -> schemas.Scope:
        """
        Throws:
            exceptions.ScopeDoesNotExist
        """
        pass

    @abstractmethod
    async def get_scopes(self) -> typing.List[schemas.Scope]:
        pass
    
    @abstractmethod
    async def delete_scope(self, scope_name: str) -> None:
        pass

######################################## Implementations ########################################

class OLTPScopeManager(ScopeManager):

    def __init__(self, engine: Engine) -> None:
        self.engine = engine

    async def create_scope(self, scope: schemas.Scope) -> None:
        scope_db = models.Scope(
            **asdict(scope)
        )
        with Session(self.engine) as db:
            db.add(scope_db)
            db.commit()

    async def update_scope(self, scope: schemas.Scope) -> None:
        pass
    
    async def get_scope(self, scope_name: str) -> schemas.Scope:
        with Session(self.engine) as db:
            scope_db = db.query(models.Scope).filter(models.Scope.name == scope_name).first()
        
        if(scope_db is None):
            raise exceptions.ScopeDoesNotExist()
        
        return scope_db.to_schema()

    async def get_scopes(self) -> typing.List[schemas.Scope]:

        with Session(self.engine) as db:
            scopes_db: typing.List[models.Scope] = db.query(models.Scope).all()
        return [scope_db.to_schema() for scope_db in scopes_db]
    
    async def delete_scope(self, scope_name: str) -> None:
        with Session(self.engine) as db:
            delete(models.Scope).where(models.Scope.name == scope_name)
            db.commit()