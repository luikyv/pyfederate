import uvicorn
from sqlalchemy import create_engine

from auth_server.auth_manager import manager as auth_manager
from auth_server.utils.managers.scope_manager import OLTPScopeManager
from auth_server.utils.managers.client_manager import OLTPClientManager
from auth_server.utils.managers.token_manager import OLTPTokenModelManager
from auth_server.utils.constants import DATABASE_URL
from auth_server.utils import models
from auth_server.routes.core import app

if(__name__=="__main__"):
    
    engine = create_engine(
        DATABASE_URL, connect_args={"check_same_thread": False}
    )
    models.Base.metadata.create_all(bind=engine)
    auth_manager.token_model_manager = OLTPTokenModelManager(engine=engine)
    auth_manager.scope_manager = OLTPScopeManager(engine=engine)
    auth_manager.client_manager = OLTPClientManager(engine=engine)

    assert auth_manager.is_ready(), "The auth manager is missing configurations"

    uvicorn.run("main:app", host="0.0.0.0", port=8000)