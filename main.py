from sqlalchemy import create_engine

from auth_server.auth_manager import manager as auth_manager
from auth_server.utils.managers.scope_manager import OLTPScopeManager
from auth_server.utils.managers.client_manager import OLTPClientManager
from auth_server.utils.managers.token_manager import OLTPTokenModelManager
from auth_server.utils.managers.session_manager import MockedSessionManager
from auth_server.utils.constants import DATABASE_URL
from auth_server.utils import models, schemas
from auth_server.routes.core import app

from fastapi import Request, Response, status
from auth_server.utils import constants, schemas
a = 0
async def get_identity_step(
    session: schemas.SessionInfo,
    request: Request,
    response: Response
) -> constants.AuthnStatus:
    global a
    response.media_type = "text/html"
    response.status_code = status.HTTP_200_OK
    response.body = response.render(f'<form action="/authorize/{session.callback_id}" method="post"> <input type="submit" value="User"> </form>')
    response.init_headers(response.headers)
    if(a == 0):
        a = a + 1
        return constants.AuthnStatus.IN_PROGRESS
    return constants.AuthnStatus.SUCCESS

async def get_password_step(
    session: schemas.SessionInfo,
    request: Request,
    response: Response
) -> constants.AuthnStatus:

    global a
    response.status_code = status.HTTP_200_OK
    response.media_type = "text/html"
    response.body =  response.render(f'<form action="/authorize/{session.callback_id}" method="post"> <input type="submit" value="Password"> </form>')
    response.init_headers(response.headers)
    if(a == 1):
        a = a + 1
        return constants.AuthnStatus.IN_PROGRESS
    return constants.AuthnStatus.SUCCESS

if(__name__=="__main__"):
    
    engine = create_engine(
        DATABASE_URL, connect_args={"check_same_thread": False}
    )
    models.Base.metadata.create_all(bind=engine)
    auth_manager.token_model_manager = OLTPTokenModelManager(engine=engine)
    auth_manager.scope_manager = OLTPScopeManager(engine=engine)
    auth_manager.client_manager = OLTPClientManager(engine=engine)
    auth_manager.session_manager = MockedSessionManager()

    password_authn_step = schemas.AuthnStep(
        id="password",
        authn_func=get_password_step,
        success_next_step=None,
        failure_next_step=None
    )

    identity_authn_step = schemas.AuthnStep(
        id="identity",
        authn_func=get_identity_step,
        success_next_step=password_authn_step,
        failure_next_step=None
    )

    my_policy = schemas.AuthnPolicy(
        is_available=lambda: True,
        first_step=identity_authn_step
    )
    auth_manager.register_authn_policy(authn_policy=my_policy)

    auth_manager.run(app=app)