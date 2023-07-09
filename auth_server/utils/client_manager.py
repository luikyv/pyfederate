from typing import Dict

from .interfaces import ClientManager
from .schemas import Client

class MockedClientManager(ClientManager):

    def __init__(self,) -> None:
        self.clients: Dict[str, Client] = {
            "luiky": Client(client_id="luiky", client_secret="pass")
        }

    async def create_client(self, client: Client) -> None:
        self.clients[client.client_id] = client

    async def update_client(self, client: Client) -> None:
        self.clients[client.client_id] = client
    
    async def get_client(self, client_id: str) -> Client:
        return self.clients[client_id]
    
    async def delete_client(self, client_id: str) -> None:
        self.clients.pop(client_id)