from .scope import APIScopeManager
from .token import APITokenModelManager
from .client import APIClientManager
from ..utils.tools import singleton


@singleton
class AuthManager:
    def __init__(
        self,
    ) -> None:
        self._scope_manager: APIScopeManager | None = None
        self._token_model_manager: APITokenModelManager | None = None
        self._client_manager: APIClientManager | None = None
        # self._session_manager: SessionManager | None = None
        # self.authn_policies: List[schemas.AuthnPolicy] = []

    @property
    def scope_manager(self) -> APIScopeManager:
        if self._scope_manager is None:
            raise RuntimeError()
        return self._scope_manager

    @scope_manager.setter
    def scope_manager(self, scope_manager: APIScopeManager) -> None:
        if self._scope_manager is not None:
            raise RuntimeError()
        self._scope_manager = scope_manager

    @property
    def token_model_manager(self) -> APITokenModelManager:
        if self._token_model_manager is None:
            raise RuntimeError()
        return self._token_model_manager

    @token_model_manager.setter
    def token_model_manager(self, token_model_manager: APITokenModelManager) -> None:
        if self._token_model_manager is not None:
            raise RuntimeError()
        self._token_model_manager = token_model_manager

    @property
    def client_manager(self) -> APIClientManager:
        if self._client_manager is None:
            raise RuntimeError()
        return self._client_manager

    @client_manager.setter
    def client_manager(self, client_manager: APIClientManager) -> None:
        if self._client_manager is not None:
            raise RuntimeError()
        self._client_manager = client_manager
