import typing
from dataclasses import asdict
from sqlalchemy import delete, Engine
from sqlalchemy.orm import Session
import typing
from abc import ABC, abstractmethod

from ..tools import hash_secret
from .. import models
from .. import schemas
from .. import exceptions

class ClientManager(ABC):

    @abstractmethod
    async def create_client(self, client: schemas.ClientUpsert) -> schemas.Client:
        """
        Throws:
            exceptions.ClientAlreadyExists
        """
        pass

    @abstractmethod
    async def update_client(self, client: schemas.Client) -> schemas.Client:
        """
        Throws:
            exceptions.ClientDoesNotExist
        """
        pass
    
    @abstractmethod
    async def get_client(self, client_id: str) -> schemas.Client:
        """
        Throws:
            exceptions.ClientDoesNotExist
        """
        pass

    @abstractmethod
    async def get_clients(self) -> typing.List[schemas.Client]:
        pass
    
    @abstractmethod
    async def delete_client(self, client_id: str) -> None:
        pass

class MockedClientManager(ClientManager):

    def __init__(self,) -> None:
        self.clients: typing.Dict[str, schemas.Client] = {}

    async def create_client(self, client: schemas.ClientUpsert) -> None:
        self.clients[client.id] = schemas.Client(**asdict(client), hashed_secret=hash_secret(secret=client.secret))

    async def update_client(self, client: schemas.Client) -> None:
        self.clients[client.id] = client
    
    async def get_client(self, client_id: str) -> schemas.Client:
        return self.clients[client_id]
    
    async def delete_client(self, client_id: str) -> None:
        self.clients.pop(client_id)

class OLTPClientManager(ClientManager):

    def __init__(self, engine: Engine) -> None:
        self.engine = engine

    async def create_client(self, client: schemas.ClientUpsert) -> schemas.Client:
        
        with Session(self.engine) as db:
            
            client_db = models.Client(**client.to_db_dict())
            scopes_db: typing.List[models.Scope] = db.query(models.Scope).filter(models.Scope.name.in_(client.scopes)).all()
            client_db.scopes = scopes_db
            
            db.add(client_db)
            db.commit()
        
            return client_db.to_schema(secret=client.secret)

    async def update_client(self, client: schemas.Client) -> schemas.Client:
        raise RuntimeError()
    
    async def get_client(self, client_id: str) -> schemas.Client:

        with Session(self.engine) as db:
            client_db = db.query(models.Client).filter(models.Client.id == client_id).first()
        
        if(client_db is None):
            raise exceptions.ClientDoesNotExist()
        
        return client_db.to_schema()
    
    async def get_clients(self) -> typing.List[schemas.Client]:

        with Session(self.engine) as db:
            clients_db: typing.List[models.Client] = db.query(models.Client).all()
        return [client_db.to_schema() for client_db in clients_db]
    
    async def delete_client(self, client_id: str) -> None:
        with Session(self.engine) as db:
            delete(models.Client).where(models.Client.id == client_id)
            db.commit()