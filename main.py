import asyncio
from fastapi import Request
from fastapi.templating import Jinja2Templates
import secrets

import auth_server
import mocked_env
from auth_server.auth_manager import manager
from auth_server.utils import schemas, telemetry

######################################## Vars ########################################

CORRECT_PASSWORD = "password"
templates = Jinja2Templates(directory="templates")
logger = telemetry.get_logger(__name__)


######################################## Functions ########################################


async def get_identity_step(
    session: schemas.AuthnSession,
    request: Request,
) -> schemas.AuthnStepResult:

    form_data = await request.form()
    user_id: str | None = form_data.get("username")  # type: ignore
    if user_id is None:
        return schemas.AuthnStepInProgressResult(
            response=templates.TemplateResponse(
                "identity.html",
                {"request": request, "callback_id": session.callback_id},
            )
        )

    session.user_id = user_id
    return schemas.AuthnStepSuccessResult()


async def get_password_step(
    session: schemas.AuthnSession,
    request: Request,
) -> schemas.AuthnStepResult:

    form_data = await request.form()
    password: str | None = form_data.get("password")  # type: ignore
    if password is None:
        return schemas.AuthnStepInProgressResult(
            response=templates.TemplateResponse(
                "password.html",
                {"request": request, "callback_id": session.callback_id},
            )
        )

    if not secrets.compare_digest(CORRECT_PASSWORD, password):
        return schemas.AuthnStepInProgressResult(
            response=templates.TemplateResponse(
                "password.html",
                {
                    "request": request,
                    "callback_id": session.callback_id,
                    "error": "Invalid password. Try typing password.",
                },
            )
        )

    return schemas.AuthnStepSuccessResult()


async def get_confirmation_step(
    session: schemas.AuthnSession,
    request: Request,
) -> schemas.AuthnStepResult:

    form_data = await request.form()
    confirm: str | None = form_data.get("confirm")  # type: ignore
    if confirm is None:
        return schemas.AuthnStepInProgressResult(
            response=templates.TemplateResponse(
                "confirmation.html",
                {
                    "request": request,
                    "callback_id": session.callback_id,
                    "client_id": session.client_id,
                    "scopes": session.requested_scopes,
                },
            )
        )

    return schemas.AuthnStepSuccessResult()


######################################## Policy ########################################

confirmation_authn_step = schemas.AuthnStep(
    id="confirmation",
    authn_func=get_confirmation_step,
    success_next_step=None,
    failure_next_step=None,
)

password_authn_step = schemas.AuthnStep(
    id="password",
    authn_func=get_password_step,
    success_next_step=confirmation_authn_step,
    failure_next_step=None,
)

identity_authn_step = schemas.AuthnStep(
    id="identity",
    authn_func=get_identity_step,
    success_next_step=password_authn_step,
    failure_next_step=None,
)

my_policy = schemas.AuthnPolicy(
    id="my_policy",
    is_available=lambda client, request: True,
    first_step=identity_authn_step,
    get_extra_token_claims=lambda session: {"new_claim": "my_new_claim"},
)

######################################## Main ########################################

if __name__ == "__main__":

    manager.setup_in_memory_env()
    manager.register_authn_policy(authn_policy=my_policy)
    asyncio.run(mocked_env.setup_mocked_env())
    auth_server.run()
