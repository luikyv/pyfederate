from .utils.interfaces import ScopeManager, ClientManager

class AuthManager():

    def __init__(
        self,
    ) -> None:
        self._client_manager = None
        self._scope_manager = None

    @property
    def client_manager(self) -> ClientManager:
        if(self._client_manager is None):
            raise RuntimeError()
        return self._client_manager
    
    @client_manager.setter
    def client_manager(self, client_manager: ClientManager) -> None:
        if(self._client_manager is not None):
            raise RuntimeError()
        self._client_manager = client_manager
    
    @property
    def scope_manager(self) -> ScopeManager:
        if(self._scope_manager is None):
            raise RuntimeError()
        return self._scope_manager
    
    @scope_manager.setter
    def scope_manager(self, scope_manager: ScopeManager) -> None:
        if(self._scope_manager is not None):
            raise RuntimeError()
        self._scope_manager = scope_manager

manager = AuthManager()