from .scope import ScopeCRUDManager
from .token import TokenModelCRUDManager
from .client import ClientCRUDManager
from .session import AuthnSessionCRUDManager, TokenSessionCRUDManager
from ..utils.tools import singleton


@singleton
class AuthCRUDManager:
    def __init__(
        self,
    ) -> None:
        self._scope_manager: ScopeCRUDManager | None = None
        self._token_model_manager: TokenModelCRUDManager | None = None
        self._client_manager: ClientCRUDManager | None = None
        self._authn_session_manager: AuthnSessionCRUDManager | None = None
        self._token_session_manager: TokenSessionCRUDManager | None = None

    @classmethod
    def get_manager(cls) -> "AuthCRUDManager":
        return AuthCRUDManager()

    @property
    def scope_manager(self) -> ScopeCRUDManager:
        if self._scope_manager is None:
            raise RuntimeError()
        return self._scope_manager

    @scope_manager.setter
    def scope_manager(self, scope_manager: ScopeCRUDManager) -> None:
        if self._scope_manager is not None:
            raise RuntimeError()
        self._scope_manager = scope_manager

    @property
    def token_model_manager(self) -> TokenModelCRUDManager:
        if self._token_model_manager is None:
            raise RuntimeError()
        return self._token_model_manager

    @token_model_manager.setter
    def token_model_manager(self, token_model_manager: TokenModelCRUDManager) -> None:
        if self._token_model_manager is not None:
            raise RuntimeError()
        self._token_model_manager = token_model_manager

    @property
    def client_manager(self) -> ClientCRUDManager:
        if self._client_manager is None:
            raise RuntimeError()
        return self._client_manager

    @client_manager.setter
    def client_manager(self, client_manager: ClientCRUDManager) -> None:
        if self._client_manager is not None:
            raise RuntimeError()
        self._client_manager = client_manager

    @property
    def authn_session_manager(self) -> AuthnSessionCRUDManager:
        if self._authn_session_manager is None:
            raise RuntimeError()
        return self._authn_session_manager

    @authn_session_manager.setter
    def authn_session_manager(
        self, authn_session_manager: AuthnSessionCRUDManager
    ) -> None:
        if self._authn_session_manager is not None:
            raise RuntimeError()
        self._authn_session_manager = authn_session_manager
    
    @property
    def token_session_manager(self) -> TokenSessionCRUDManager:
        if self._token_session_manager is None:
            raise RuntimeError()
        return self._token_session_manager

    @token_session_manager.setter
    def token_session_manager(
        self, token_session_manager: AuthnSessionCRUDManager
    ) -> None:
        if self._token_session_manager is not None:
            raise RuntimeError()
        self._token_session_manager = token_session_manager
