import asyncio
from fastapi import Request
from fastapi.templating import Jinja2Templates
import secrets

import auth_server
from auth_server.auth_manager import manager
from auth_server.utils import schemas, constants, telemetry, tools


CORRECT_PASSWORD = "password"
templates = Jinja2Templates(directory="templates")
logger = telemetry.get_logger(__name__)


async def get_identity_step(
    session: schemas.AuthnSession,
    request: Request,
) -> schemas.AuthnStepResult:

    form_data = await request.form()
    user_id: str | None = form_data.get("username")  # type: ignore
    logger.info(f"form = {form_data}")
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


async def setup_mocked_env() -> None:

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
    manager.register_authn_policy(authn_policy=my_policy)

    await manager.token_model_manager.create_token_model(
        token_model=schemas.TokenModelUpsert(
            id="my_token_model",
            issuer="my_company",
            expires_in=300,
            token_type=constants.TokenType.JWT,
            key_id="my_key",
            is_refreshable=True,
        )
    )
    await manager.scope_manager.create_scope(
        scope=schemas.ScopeUpsert(name="profile", description="profile")
    )
    await manager.scope_manager.create_scope(
        scope=schemas.ScopeUpsert(name="photos", description="photos")
    )
    client = schemas.ClientUpsert(
        id="auth_client",
        authn_method=constants.ClientAuthnMethod.CLIENT_SECRET_POST,
        redirect_uris=["http://localhost:8080/callback"],
        response_types=[constants.ResponseType.CODE],
        grant_types=[
            constants.GrantType.CLIENT_CREDENTIALS,
            constants.GrantType.AUTHORIZATION_CODE,
            constants.GrantType.REFRESH_TOKEN,
        ],
        scopes=["profile", "photos"],
        is_pkce_required=False,
        token_model_id="my_token_model",
    )
    client.secret = "secret_123456789"
    client.hashed_secret = tools.hash_secret(secret=client.secret)
    client = await manager.client_manager.create_client(client=client)


if __name__ == "__main__":

    manager.setup_in_memory_env()
    asyncio.run(setup_mocked_env())
    auth_server.run()
