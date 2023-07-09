from fastapi import FastAPI

from auth_server.routes import oauth
from auth_server.auth_manager import manager as auth_manager
from auth_server.utils.client_manager import MockedClientManager

auth_manager.client_manager = MockedClientManager()

app = FastAPI()
app.include_router(oauth.router)
