import uvicorn
from .routes.core import app
from .auth_manager import manager
from .utils import constants


def run() -> None:
    manager.check_config()
    uvicorn.run(app, host="0.0.0.0", port=constants.SERVER_PORT)
