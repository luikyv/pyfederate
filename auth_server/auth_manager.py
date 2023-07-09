from .utils.interfaces import ClientManager

class AuthManager():

    def __init__(
        self,
    ) -> None:
        self._client_manager = None

    @property
    def client_manager(self) -> ClientManager:
        if(self._client_manager is None):
            raise RuntimeError()
        return self._client_manager
    
    @client_manager.setter
    def client_manager(self, client_manager: ClientManager) -> None:
        self._client_manager = client_manager

manager = AuthManager()