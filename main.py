from sqlalchemy import create_engine

import auth_server
from auth_server.auth_manager import manager
from auth_server.utils.managers.scope_manager import OLTPScopeManager
from auth_server.utils.managers.client_manager import OLTPClientManager
from auth_server.utils.managers.token_manager import OLTPTokenModelManager
from auth_server.utils.managers.session_manager import MockedSessionManager
from auth_server.utils import models

if(__name__=="__main__"):
    
    engine = create_engine(
        "sqlite:///./sql_app.db", connect_args={"check_same_thread": False}
    )
    models.Base.metadata.create_all(bind=engine)
    manager.token_model_manager = OLTPTokenModelManager(engine=engine)
    manager.scope_manager = OLTPScopeManager(engine=engine)
    manager.client_manager = OLTPClientManager(engine=engine)
    manager.session_manager = MockedSessionManager()

    auth_server.run()