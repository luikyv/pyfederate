from typing import Dict, List
from abc import ABC, abstractmethod

from .token import InternalTokenModelManager
from ..schemas.client import (
    ClientIn,
    ClientOut,
    ClientInfo,
    ClientAuthnInfoIn,
    ClientAuthnInfoOut,
)
from ..utils.client import (
    Client,
    ClientAuthenticator,
    NoneAuthenticator,
    SecretAuthenticator,
)
from ..utils.token import TokenModel
from ..utils.telemetry import get_logger
from ..utils.tools import remove_oldest_item, hash_secret
from ..utils.constants import ClientAuthnMethod
from .exceptions import EntityAlreadyExistsException, EntityDoesNotExistException

logger = get_logger(__name__)


class InternalClientManager(ABC):
    @abstractmethod
    async def get_client(self, client_id: str) -> Client:
        """
        Throws:
            exceptions.EntityDoesNotExistException
        """
        pass


class APIClientManager(ABC):
    @abstractmethod
    async def create_client(self, client: ClientIn) -> None:
        """
        Throws:
            exceptions.EntityAlreadyExistsException
        """
        pass

    @abstractmethod
    async def update_client(self, client_id: str, client: ClientIn) -> None:
        """
        Throws:
            exceptions.EntityDoesNotExistException
        """
        pass

    @abstractmethod
    async def get_client_out(self, client_id: str) -> ClientOut:
        """
        Throws:
            exceptions.EntityDoesNotExistException
        """
        pass

    @abstractmethod
    async def get_clients_out(self) -> List[ClientOut]:
        pass

    @abstractmethod
    async def delete_client(self, client_id: str) -> None:
        pass


class InMemoryClientManager(APIClientManager, InternalClientManager):
    def __init__(
        self, token_manager: InternalTokenModelManager, max_number: int = 10
    ) -> None:
        self._max_number = max_number
        self._token_manager = token_manager
        self._clients: Dict[str, ClientIn] = {}

    async def create_client(self, client: ClientIn) -> None:

        if client.client_id in self._clients:
            logger.info(f"Client with ID: {client.client_id} already exists")
            raise EntityAlreadyExistsException()
        if len(self._clients) >= self._max_number:
            remove_oldest_item(self._clients)

        self._clients[client.client_id] = client

    async def update_client(self, client: ClientIn) -> None:

        if client.client_id not in self._clients:
            logger.info(f"Client with ID: {client.client_id} does not exist")
            raise EntityDoesNotExistException()

        self._clients[client.client_id] = client

    @abstractmethod
    async def get_client(self, client_id: str) -> Client:
        """
        Throws:
            exceptions.EntityDoesNotExistException
        """

        client: ClientIn | None = self._clients.get(client_id, None)
        if not client:
            raise EntityDoesNotExistException()
        token_model: TokenModel = await self._token_manager.get_token_model(
            token_model_id=client.token_model_id
        )

        return Client(
            info=ClientInfo(
                client_id=client.client_id,
                redirect_uris=client.redirect_uris,
                response_types=client.response_types,
                grant_types=client.grant_types,
                scopes=client.scopes,
                is_pkce_required=client.is_pkce_required,
                extra_params=client.extra_params,
            ),
            authenticator=self._build_client_authenticator(
                client_authn_info=client.authn_info
            ),
            token_model=token_model,
        )

    def _build_client_authenticator(
        self, client_authn_info: ClientAuthnInfoIn
    ) -> ClientAuthenticator:

        if client_authn_info.authn_info == ClientAuthnMethod.NONE:
            return NoneAuthenticator()
        elif client_authn_info.authn_info == ClientAuthnMethod.CLIENT_SECRET_POST:
            return SecretAuthenticator(
                hashed_secret=client_authn_info.secret
                if client_authn_info.secret
                else ""
            )

        raise RuntimeError("Invalid client authentication method")

    async def get_client_out(self, client_id: str) -> ClientOut:

        client: ClientIn | None = self._clients.get(client_id, None)
        if not client:
            logger.info(f"Client with ID: {client_id} does not exist")
            raise EntityDoesNotExistException()

        return ClientOut(
            **client.model_dump(),
            authn_info=ClientAuthnInfoOut(
                authn_info=client.authn_info.authn_info,
                hashed_secret=hash_secret(client.authn_info.secret)
                if client.authn_info.secret
                else None,
            ),
        )

    async def get_clients_out(self) -> List[ClientOut]:
        return [
            ClientOut(
                **client.model_dump(),
                authn_info=ClientAuthnInfoOut(
                    authn_info=client.authn_info.authn_info,
                    hashed_secret=hash_secret(client.authn_info.secret)
                    if client.authn_info.secret
                    else None,
                ),
            )
            for client in self._clients.values()
        ]

    async def delete_client(self, client_id: str) -> None:
        self._clients.pop(client_id)
