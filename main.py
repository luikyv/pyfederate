import asyncio
from dataclasses import asdict
from sqlalchemy import create_engine
from fastapi import Request
from fastapi.responses import HTMLResponse

from urllib.parse import quote
import auth_server
from auth_server.auth_manager import manager
from auth_server.utils.managers.scope_manager import MockedScopeManager, OLTPScopeManager
from auth_server.utils.managers.client_manager import MockedClientManager, OLTPClientManager
from auth_server.utils.managers.token_manager import MockedTokenModelManager, OLTPTokenModelManager
from auth_server.utils.managers.session_manager import MockedSessionManager
from auth_server.utils import models, schemas, constants, telemetry


logger = telemetry.get_logger(__name__)

a = 0
async def get_identity_step(
    session: schemas.SessionInfo,
    request: Request,
) -> schemas.AuthnStepResult:
    global a
    if(a == 0):
        a = a + 1
        return schemas.AuthnStepInProgressResult(response=HTMLResponse(
            content=f'<form action="/authorize/{session.callback_id}" method="post"> <input type="submit" value="User"> </form>'
        ))
    session.user_id = "luiky"
    return schemas.AuthnStepSuccessResult()

async def get_password_step(
    session: schemas.SessionInfo,
    request: Request,
) -> schemas.AuthnStepResult:

    global a
    if(a == 1):
        a = a + 1
        return schemas.AuthnStepInProgressResult(response=HTMLResponse(
            content=f'<form action="/authorize/{session.callback_id}" method="post"> <input type="submit" value="Password"> </form>'
        ))
    return schemas.AuthnStepSuccessResult()

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
    id="my_policy",
    is_available=lambda client, request: True,
    first_step=identity_authn_step,
    get_extra_token_claims=lambda session: {"new_claim": "my_new_claim"}
)
manager.register_authn_policy(authn_policy=my_policy)

async def setup_mocked_env() -> None:
    await manager.token_model_manager.create_token_model(
        token_model=schemas.TokenModelUpsert(
            id="my_token_model",
            issuer="my_company",
            expires_in=300,
            token_type=constants.TokenType.JWT,
            key_id="my_key"
        )
    )
    await manager.scope_manager.create_scope(
        scope=schemas.ScopeUpsert(
            name="admin",
            description="admin"
        )
    )
    client=schemas.ClientUpsert(
        redirect_uris=["http://localhost:8080/home"],
        response_types=[constants.ResponseType.CODE],
        scopes=["admin"],
        token_model_id="my_token_model",
    )
    await manager.client_manager.create_client(
        client=client
    )
    logger.info(str(asdict(client)))
    logger.info(f"http://localhost:8000/authorize?client_id={client.id}&redirect_uri={quote('http://localhost:8080/home')}&response_type=code&scope=admin&state=random")


if(__name__=="__main__"):
    
    # engine = create_engine(
    #     "sqlite:///./sql_app.db", connect_args={"check_same_thread": False}
    # )
    # models.Base.metadata.create_all(bind=engine)
    # manager.token_model_manager = OLTPTokenModelManager(engine=engine)
    # manager.scope_manager = OLTPScopeManager(engine=engine)
    # manager.client_manager = OLTPClientManager(engine=engine)
    # manager.session_manager = MockedSessionManager()

    manager.token_model_manager = MockedTokenModelManager()
    manager.scope_manager = MockedScopeManager()
    manager.client_manager = MockedClientManager(token_manager=manager.token_model_manager)
    manager.session_manager = MockedSessionManager()

    asyncio.run(setup_mocked_env())

    auth_server.run()