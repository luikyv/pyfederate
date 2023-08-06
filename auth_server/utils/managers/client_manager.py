import typing
from sqlalchemy import delete, Engine
from sqlalchemy.orm import Session
from abc import ABC, abstractmethod

from .. import models, schemas, telemetry, tools, exceptions
from ..constants import ClientAuthnMethod
from .token_manager import TokenModelManager

logger = telemetry.get_logger(__name__)

######################################## Interfaces ########################################


class ClientManager(ABC):
    @abstractmethod
    async def create_client(self, client: schemas.ClientUpsert) -> schemas.Client:
        """
        Throws:
            exceptions.ClientAlreadyExists
        """
        pass

    @abstractmethod
    async def update_client(self, client: schemas.ClientUpsert) -> schemas.Client:
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


######################################## Implementations ########################################

#################### Mock ####################


class InMemoryClientManager(ClientManager):
    def __init__(self, token_manager: TokenModelManager, max_number: int = 10) -> None:
        self._max_number = max_number
        self._token_manager = token_manager
        self._clients: typing.Dict[str, schemas.Client] = {}

    async def create_client(self, client: schemas.ClientUpsert) -> schemas.Client:

        if client.id in self._clients:
            logger.info(f"Client with ID: {client.id} already exists")
            raise exceptions.ClientAlreadyExistsException()

        client_ = schemas.Client(
            id=client.id,
            authn_method=client.authn_method,
            redirect_uris=client.redirect_uris,
            response_types=client.response_types,
            grant_types=client.grant_types,
            scopes=client.scopes,
            is_pkce_required=client.is_pkce_required,
            token_model=await self._token_manager.get_token_model(
                token_model_id=client.token_model_id
            ),
            hashed_secret=client.hashed_secret,
            secret=client.secret,
            extra_params=client.extra_params,
        )

        if len(self._clients) >= self._max_number:
            tools.remove_oldest_item(self._clients)
        # Save the client without its secret
        self._clients[client.id] = client_.model_copy(update={"secret": None})

        return client_

    async def update_client(self, client: schemas.ClientUpsert) -> schemas.Client:

        if client.id not in self._clients:
            logger.info(f"Client with ID: {client.id} does not exist")
            raise exceptions.ClientDoesNotExistException()

        client_ = schemas.Client(
            id=client.id,
            authn_method=client.authn_method,
            redirect_uris=client.redirect_uris,
            response_types=client.response_types,
            grant_types=client.grant_types,
            scopes=client.scopes,
            is_pkce_required=client.is_pkce_required,
            token_model=await self._token_manager.get_token_model(
                token_model_id=client.token_model_id
            ),
            hashed_secret=client.hashed_secret,
            secret=client.secret,
            extra_params=client.extra_params,
        )
        # Save the client without its secret
        self._clients[client.id] = client_.model_copy(update={"secret": None})

        return client_

    async def get_client(self, client_id: str) -> schemas.Client:

        client: schemas.Client | None = self._clients.get(client_id, None)
        if not client:
            logger.info(f"Client with ID: {client_id} does not exist")
            raise exceptions.ClientDoesNotExistException()

        return client

    async def get_clients(self) -> typing.List[schemas.Client]:
        return list(self._clients.values())

    async def delete_client(self, client_id: str) -> None:
        self._clients.pop(client_id)


#################### OLTP ####################


class OLTPClientManager(ClientManager):
    def __init__(self, engine: Engine) -> None:
        self.engine = engine

    async def create_client(self, client: schemas.ClientUpsert) -> schemas.Client:

        with Session(self.engine) as db:

            scopes_db: typing.List[models.Scope] = (
                db.query(models.Scope)
                .filter(models.Scope.name.in_(client.scopes))
                .all()
            )
            client_db = models.Client.to_db_model(client=client, scopes=scopes_db)

            db.add(client_db)
            db.commit()

            return client_db.to_schema(secret=client.secret)

    async def update_client(self, client: schemas.ClientUpsert) -> schemas.Client:
        raise RuntimeError()

    async def get_client(self, client_id: str) -> schemas.Client:

        with Session(self.engine) as db:
            client_db: models.Client | None = (
                db.query(models.Client).filter(models.Client.id == client_id).first()
            )

        if client_db is None:
            raise exceptions.ClientDoesNotExistException()

        return client_db.to_schema()

    async def get_clients(self) -> typing.List[schemas.Client]:

        with Session(self.engine) as db:
            clients_db: typing.List[models.Client] = db.query(models.Client).all()
        return [client_db.to_schema() for client_db in clients_db]

    async def delete_client(self, client_id: str) -> None:
        with Session(self.engine) as db:
            delete(models.Client).where(models.Client.id == client_id)
            db.commit()
