import uvicorn
from .routes.core import app
from .utils.config import SERVER_PORT

def run() -> None:
    uvicorn.run(app, host="0.0.0.0", port=SERVER_PORT)
