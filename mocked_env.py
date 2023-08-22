from typing import Annotated
from fastapi import Query, Request, Response
from fastapi.templating import Jinja2Templates
import os

from auth_server.auth_manager import manager
from auth_server.utils import schemas, constants, tools
from auth_server.routes.core import app

templates = Jinja2Templates(directory="templates")


@app.get("/callback", tags=["example"])
def callback(
    request: Request,
    code: Annotated[str | None, Query()] = None,
    state: Annotated[str | None, Query()] = None,
    error: Annotated[str | None, Query()] = None,
    error_description: Annotated[str | None, Query()] = None,
) -> Response:

    if code is None:
        return templates.TemplateResponse(
            "callback_page.html",
            {"request": request, "error": error},
        )

    return templates.TemplateResponse(
        "callback_page.html",
        {"request": request, "code": code},
    )


async def setup_mocked_env() -> None:

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
        redirect_uris=[f"{os.getenv('APP_DOMAIN', 5)}/callback"],
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
