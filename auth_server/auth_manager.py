from typing import List
from fastapi import Request
import asyncio

from .utils.managers.token_manager import TokenModelManager
from .utils.managers.scope_manager import ScopeManager
from .utils.managers.client_manager import ClientManager
from .utils.managers.session_manager import SessionManager
from .utils import constants, schemas, tools, exceptions


@tools.singleton
class AuthManager():

    def __init__(
        self,
    ) -> None:
        self._token_model_manager: TokenModelManager | None = None
        self._scope_manager: ScopeManager | None = None
        self._client_manager: ClientManager | None = None
        self._session_manager: SessionManager | None = None
        self.authn_policies: List[schemas.AuthnPolicy] = []

    @property
    def token_model_manager(self) -> TokenModelManager:
        if (self._token_model_manager is None):
            raise RuntimeError()
        return self._token_model_manager

    @token_model_manager.setter
    def token_model_manager(self, token_model_manager: TokenModelManager) -> None:
        if (self._token_model_manager is not None):
            raise RuntimeError()
        self._token_model_manager = token_model_manager

    @property
    def scope_manager(self) -> ScopeManager:
        if (self._scope_manager is None):
            raise RuntimeError()
        return self._scope_manager

    @scope_manager.setter
    def scope_manager(self, scope_manager: ScopeManager) -> None:
        if (self._scope_manager is not None):
            raise RuntimeError()
        self._scope_manager = scope_manager

    @property
    def client_manager(self) -> ClientManager:
        if (self._client_manager is None):
            raise RuntimeError()
        return self._client_manager

    @client_manager.setter
    def client_manager(self, client_manager: ClientManager) -> None:
        if (self._client_manager is not None):
            raise RuntimeError()
        self._client_manager = client_manager

    @property
    def session_manager(self) -> SessionManager:
        if (self._session_manager is None):
            raise RuntimeError()
        return self._session_manager

    @session_manager.setter
    def session_manager(self, session_manager: SessionManager) -> None:
        if (self._session_manager is not None):
            raise RuntimeError()
        self._session_manager = session_manager

    def register_authn_policy(self, authn_policy: schemas.AuthnPolicy) -> None:
        self.authn_policies.append(authn_policy)

    def pick_policy(self, client: schemas.Client, request: Request) -> schemas.AuthnPolicy:
        available_policies: List[schemas.AuthnPolicy] = list(filter(
            lambda policy: policy.is_available(client, request),
            self.authn_policies
        ))
        if (len(available_policies) == 0):
            raise exceptions.NoAuthenticationPoliciesAvailableException()

        return available_policies[0]

    async def verify_signing_keys(self) -> bool:
        return set(constants.PRIVATE_JWKS.keys()).issuperset(set(await self.token_model_manager.get_model_key_ids()))

    def check_config(self) -> None:
        assert (
            self._token_model_manager is not None
            and self._scope_manager is not None
            and self._client_manager is not None
            and self._session_manager is not None
        ), "The auth manager is missing configurations"

        assert asyncio.run(
            self.verify_signing_keys()
        ), "There are signing keys defined in the token models that are not available"


manager = AuthManager()
