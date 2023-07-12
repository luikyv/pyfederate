from .utils.managers.token_manager import AbstractTokenModelManager
from .utils.managers.scope_manager import AbstractScopeManager
from .utils.managers.client_manager import AbstractClientManager
from .utils.managers.session_manager import SessionManager

class AuthManager():

    def __init__(
        self,
    ) -> None:
        self._token_model_manager: AbstractTokenModelManager | None = None
        self._scope_manager: AbstractScopeManager | None = None
        self._client_manager: AbstractClientManager | None = None
        self._session_manager: SessionManager | None = None
    
    @property
    def token_model_manager(self) -> AbstractTokenModelManager:
        if(self._token_model_manager is None): raise RuntimeError()
        return self._token_model_manager
    
    @token_model_manager.setter
    def token_model_manager(self, token_model_manager: AbstractTokenModelManager) -> None:
        if(self._token_model_manager is not None): raise RuntimeError()
        self._token_model_manager = token_model_manager

    @property
    def scope_manager(self) -> AbstractScopeManager:
        if(self._scope_manager is None): raise RuntimeError()
        return self._scope_manager
    
    @scope_manager.setter
    def scope_manager(self, scope_manager: AbstractScopeManager) -> None:
        if(self._scope_manager is not None): raise RuntimeError()
        self._scope_manager = scope_manager

    @property
    def client_manager(self) -> AbstractClientManager:
        if(self._client_manager is None): raise RuntimeError()
        return self._client_manager
    
    @client_manager.setter
    def client_manager(self, client_manager: AbstractClientManager) -> None:
        if(self._client_manager is not None): raise RuntimeError()
        self._client_manager = client_manager
    
    @property
    def session_manager(self) -> SessionManager:
        if(self._session_manager is None): raise RuntimeError()
        return self._session_manager
    
    @session_manager.setter
    def session_manager(self, session_manager: SessionManager) -> None:
        if(self._session_manager is not None): raise RuntimeError()
        self._session_manager = session_manager
    
    def is_ready(self) -> bool:
        return (
            self.token_model_manager is not None
            and self.scope_manager is not None
            and self.client_manager is not None
            and self.session_manager is not None
        )

manager = AuthManager()