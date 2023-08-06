from dataclasses import asdict
import typing
from sqlalchemy import delete, Engine
from sqlalchemy.orm import Session
from abc import ABC, abstractmethod

from .. import schemas, models, telemetry, exceptions, tools

logger = telemetry.get_logger(__name__)

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

#################### Mock ####################


class InMemoryScopeManager(ScopeManager):
    def __init__(self, max_number: int = 100) -> None:
        self._max_number = max_number
        self._scopes: typing.Dict[str, schemas.Scope] = {}

    async def create_scope(self, scope: schemas.ScopeUpsert) -> None:

        if scope.name in self._scopes:
            logger.info(f"{scope.name} already exists")
            raise exceptions.ScopeAlreadyExistsException()

        if len(self._scopes) >= self._max_number:
            tools.remove_oldest_item(self._scopes)
        self._scopes[scope.name] = schemas.Scope(**dict(scope))

    async def update_scope(self, scope: schemas.ScopeUpsert) -> None:

        if scope.name not in self._scopes:
            logger.info(f"{scope.name} does not exist")
            raise exceptions.ScopeDoesNotExistException()

        self._scopes[scope.name] = schemas.Scope(**scope.model_dump())

    async def get_scope(self, scope_name: str) -> schemas.Scope:

        if scope_name not in self._scopes:
            logger.info(f"{scope_name} does not exist")
            raise exceptions.ScopeDoesNotExistException()

        return self._scopes[scope_name]

    async def get_scopes(self) -> typing.List[schemas.Scope]:
        return list(self._scopes.values())

    async def delete_scope(self, scope_name: str) -> None:
        self._scopes.pop(scope_name)


#################### OLTP ####################


class OLTPScopeManager(ScopeManager):
    def __init__(self, engine: Engine) -> None:
        self.engine = engine

    async def create_scope(self, scope: schemas.Scope) -> None:
        scope_db = models.Scope.to_db_model(scope=scope)
        with Session(self.engine) as db:
            db.add(scope_db)
            db.commit()

    async def update_scope(self, scope: schemas.Scope) -> None:
        pass

    async def get_scope(self, scope_name: str) -> schemas.Scope:
        with Session(self.engine) as db:
            scope_db = (
                db.query(models.Scope).filter(models.Scope.name == scope_name).first()
            )

        if scope_db is None:
            raise exceptions.ScopeDoesNotExistException()

        return scope_db.to_schema()

    async def get_scopes(self) -> typing.List[schemas.Scope]:

        with Session(self.engine) as db:
            scopes_db: typing.List[models.Scope] = db.query(models.Scope).all()
        return [scope_db.to_schema() for scope_db in scopes_db]

    async def delete_scope(self, scope_name: str) -> None:
        with Session(self.engine) as db:
            delete(models.Scope).where(models.Scope.name == scope_name)
            db.commit()
