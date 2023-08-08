from typing import Annotated, List
from fastapi import APIRouter, status, Query, Form, Depends, Request, Response

from ..auth_manager import manager as manager
from ..utils.constants import GrantType
from ..utils import constants, telemetry, schemas, tools, helpers

logger = telemetry.get_logger(__name__)

router = APIRouter(tags=["oauth"])


@router.post(
    "/token",
    response_model=schemas.TokenResponse,
    response_model_exclude_none=True,
    status_code=status.HTTP_200_OK,
)
async def get_token(
    client: Annotated[schemas.Client, Depends(helpers.get_authenticated_client)],
    grant_type: Annotated[GrantType, Form()],
    requested_scopes: Annotated[List[str], Depends(helpers.get_scopes_as_form)],
    code: Annotated[str | None, Form(description="Authorization code")] = None,
    redirect_uri: Annotated[
        str | None, Form(description="URL informed during /authorize")
    ] = None,
    refresh_token: Annotated[
        str | None,
        Form(
            min_length=constants.REFRESH_TOKEN_LENGTH,
            max_length=constants.REFRESH_TOKEN_LENGTH,
        ),
    ] = None,
    code_verifier: Annotated[
        str | None, Form(min_length=43, max_length=128, description="PCKE extension")
    ] = None,
    correlation_id: constants.CORRELATION_ID_HEADER_TYPE = None,
) -> schemas.TokenResponse:

    grant_context = schemas.GrantContext(
        grant_type=grant_type,
        client=client,
        token_model=client.token_model,
        requested_scopes=requested_scopes,
        redirect_uri=redirect_uri,
        refresh_token=refresh_token,
        authz_code=code,
        code_verifier=code_verifier,
        correlation_id=correlation_id,
    )

    return await helpers.grant_handlers[grant_type](grant_context)


@router.get("/authorize", status_code=status.HTTP_200_OK)
async def authorize(
    request: Request,
    client: Annotated[schemas.Client, Depends(helpers.get_client_as_query)],
    response_types: Annotated[
        List[constants.ResponseType], Depends(helpers.get_response_types)
    ],
    redirect_uri: Annotated[
        str,
        Query(
            description="URL to where the user will be redirected to once he is authenticated"
        ),
    ],
    request_scopes: Annotated[List[str], Depends(helpers.get_scopes_as_query)],
    state: Annotated[
        str,
        Query(
            max_length=constants.STATE_PARAM_MAX_LENGTH,
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
        constants.CodeChallengeMethod,
        Query(description="Method used to generate the code challenge"),
    ] = constants.CodeChallengeMethod.S256,
    _: constants.CORRELATION_ID_HEADER_TYPE = None,
) -> Response:

    helpers.validate_authorization_request(
        authorize_context=schemas.AuthorizeContext(
            client=client,
            requested_scopes=request_scopes,
            response_types=response_types,
            redirect_uri=redirect_uri,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
        )
    )

    authn_policy: schemas.AuthnPolicy = manager.pick_policy(
        client=client, request=request
    )
    logger.info(f"Policy with ID: {authn_policy.id} retrieved for execution")

    session = schemas.AuthnSession(
        tracking_id=telemetry.tracking_id.get(),
        correlation_id=telemetry.correlation_id.get(),
        callback_id=tools.generate_callback_id(),
        user_id=None,
        client_id=client.id,
        redirect_uri=redirect_uri,
        state=state,
        auth_policy_id=authn_policy.id,
        next_authn_step_id=authn_policy.first_step.id,
        requested_scopes=request_scopes,
        authz_code=None,
        code_challenge=code_challenge,
        authz_code_creation_timestamp=tools.get_timestamp_now(),
    )
    await manager.session_manager.create_session(session=session)

    return await helpers.manage_authentication(session, request)


@router.post("/authorize/{callback_id}", status_code=status.HTTP_200_OK)
async def callback_authorize(
    session: Annotated[
        schemas.AuthnSession, Depends(helpers.setup_session_by_callback_id)
    ],
    request: Request,
):
    return await helpers.manage_authentication(session, request)
