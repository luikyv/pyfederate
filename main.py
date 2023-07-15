from sqlalchemy import create_engine

from auth_server.auth_manager import manager as auth_manager
from auth_server.utils.managers.scope_manager import OLTPScopeManager
from auth_server.utils.managers.client_manager import OLTPClientManager
from auth_server.utils.managers.token_manager import OLTPTokenModelManager
from auth_server.utils.managers.session_manager import MockedSessionManager
from auth_server.utils.constants import DATABASE_URL
from auth_server.utils import models
from auth_server.routes.core import app
import my_server

if(__name__=="__main__"):
    
    engine = create_engine(
        DATABASE_URL, connect_args={"check_same_thread": False}
    )
    models.Base.metadata.create_all(bind=engine)
    auth_manager.token_model_manager = OLTPTokenModelManager(engine=engine)
    auth_manager.scope_manager = OLTPScopeManager(engine=engine)
    auth_manager.client_manager = OLTPClientManager(engine=engine)
    auth_manager.session_manager = MockedSessionManager()

    auth_manager.run(app=app)