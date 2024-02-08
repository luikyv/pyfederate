from typing import Annotated, List
from fastapi import APIRouter, status, Form, Depends, Request, Response, Query

from ..crud.auth import AuthCRUDManager
from ..utils.auth import AuthnPolicy
from ..utils.telemetry import get_logger
from ..schemas.auth import AuthnSession
from ..schemas.oauth import TokenResponse, GrantContext
from ..utils.constants import (
    GrantType,
    ResponseType,
    CodeChallengeMethod,
    CORRELATION_ID_HEADER_TYPE,
)
from ..utils.oauth import get_scopes_as_form
from ..utils.client import Client
from ..utils.oauth import (
    get_authenticated_client,
    get_client_as_query,
    get_response_types_as_query,
    get_scopes_as_query,
    get_session_by_callback_id,
    validate_authorization_request,
    grant_handlers,
)

logger = get_logger(__name__)

router = APIRouter(tags=["oauth"])
auth_manager = AuthCRUDManager.get_manager()


@router.post(
    "/token",
    response_model_exclude_none=True,
    status_code=status.HTTP_200_OK,
)
async def get_token(
    client: Annotated[Client, Depends(get_authenticated_client)],
    grant_type: Annotated[GrantType, Form()],
    scopes: Annotated[List[str], Depends(get_scopes_as_form)],
    code: Annotated[str | None, Form()] = None,
    redirect_uri: Annotated[str | None, Form()] = None,
    refresh_token: Annotated[str | None, Form()] = None,
    code_verifier: Annotated[str | None, Form(min_length=43, max_length=128)] = None,
    correlation_id: CORRELATION_ID_HEADER_TYPE = None,
) -> TokenResponse:
    grant_context = GrantContext(
        grant_type=grant_type,
        scopes=scopes,
        redirect_uri=redirect_uri,
        refresh_token=refresh_token,
        authz_code=code,
        code_verifier=code_verifier,
        correlation_id=correlation_id,
    )
    return await grant_handlers[grant_type](grant_context, client)


@router.get("/authorize", status_code=status.HTTP_200_OK)
async def authorize(
    request: Request,
    client: Annotated[Client, Depends(get_client_as_query)],
    response_types: Annotated[List[ResponseType], Depends(get_response_types_as_query)],
    scopes: Annotated[List[str], Depends(get_scopes_as_query)],
    redirect_uri: Annotated[
        str,
        Query(
            description="URL to where the user will be redirected to once he is authenticated"
        ),
    ],
    state: Annotated[
        str,
        Query(
            description="Random value that will be sent as-is in the redirect_uri. It protects the client against CSRF attacks",
        ),
    ],
    code_challenge: Annotated[
        str | None,
        Query(
            description="Used by the PCKE extension. This value is the hash of the code verifier"
        ),
    ] = None,
    code_challenge_method: Annotated[
        CodeChallengeMethod,
        Query(description="Method used to generate the code challenge"),
    ] = CodeChallengeMethod.S256,
) -> Response:

    policy = AuthnPolicy.get_policy_by_initial_request(client=client, request=request)
    session = AuthnSession(
        policy_id=policy.get_id(),
        current_step_id=policy.get_first_step(),
        client_id=client.get_id(),
        redirect_uri=redirect_uri,
        response_types=response_types,
        scopes=scopes,
        state=state,
    )
    validate_authorization_request(client=client, session=session)

    response: Response = await policy.authenticate(request=request, session=session)
    await AuthCRUDManager.get_manager().authn_session_manager.create_session(
        session=session
    )
    return response


@router.post("/authorize/{callback_id}", status_code=status.HTTP_200_OK)
async def callback_authorize(
    session: Annotated[AuthnSession, Depends(get_session_by_callback_id)],
    request: Request,
):
    response: Response = await AuthnPolicy.get_policy(
        policy_id=session.policy_id
    ).authenticate(request=request, session=session)
    await AuthCRUDManager.get_manager().authn_session_manager.update_session(
        session=session
    )
    return response
