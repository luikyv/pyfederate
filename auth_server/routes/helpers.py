import typing
from fastapi import status, Query

from ..utils import constants, telemetry, schemas, exceptions
from ..utils.constants import GrantType
from ..auth_manager import manager as auth_manager

logger = telemetry.get_logger(__name__)

######################################## Dependency Functions ########################################

async def get_client(
        client_id: typing.Annotated[
            str,
            Query(min_length=constants.CLIENT_ID_LENGH, max_length=constants.CLIENT_ID_LENGH)
        ]
) -> schemas.Client:
    
    try:
        client: schemas.Client = await auth_manager.client_manager.get_client(client_id=client_id)
    except exceptions.ClientDoesNotExist:
        logger.info(f"The client with ID: {client_id} does not exists")
        raise exceptions.HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            error=constants.ErrorCode.INVALID_CLIENT,
            error_description="invalid credentials"
        )
    
    return client

async def get_authenticated_client(
        client_id: typing.Annotated[
            str,
            Query(min_length=constants.CLIENT_ID_LENGH, max_length=constants.CLIENT_ID_LENGH)
        ],
        client_secret: typing.Annotated[
            str,
            Query(max_length=constants.CLIENT_SECRET_LENGH, min_length=constants.CLIENT_SECRET_LENGH)
        ]       
) -> schemas.Client:
    
    client: schemas.Client = await get_client(client_id=client_id)

    if(not client.is_authenticated(client_secret=client_secret)):
        logger.info(f"The client with ID: {client_id} is not authenticated")
        raise exceptions.HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            error=constants.ErrorCode.INVALID_CLIENT,
            error_description="invalid credentials"
        )
    
    return client

######################################## Grant Handlers ########################################

#################### Client Credentials ####################

def client_credentials_token_handler(
    grant_context: schemas.GrantContext
) -> schemas.TokenResponse:
    
    client: schemas.Client = grant_context.client
    # Check if the scopes requested are available to the client
    if(not client.are_scopes_allowed(requested_scopes=grant_context.requested_scopes)):
        raise exceptions.HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            error=constants.ErrorCode.INVALID_SCOPE,
            error_description="the client does not have access to the required scopes"
        )

    token_model: schemas.TokenModel = client.token_model
    token: schemas.BearerToken = token_model.generate_token(
        client_id=client.id,
        subject=client.id,
        # If the client didn't inform any scopes, send all the available ones
        scopes=grant_context.requested_scopes if grant_context.requested_scopes else client.scopes
    )
    return schemas.TokenResponse(
        access_token=token.token,
        expires_in=token_model.expires_in
    )

#################### Handler Object ####################

def not_implemented_token_handler(
    grant_context: schemas.GrantContext
) -> schemas.TokenResponse:
    raise exceptions.HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            error=constants.ErrorCode.ACCESS_DENIED,
            error_description="Problem"
        )

grant_handlers: typing.Dict[
    GrantType,
    typing.Callable[
        [schemas.GrantContext], schemas.TokenResponse
    ]
] = {
    GrantType.CLIENT_CREDENTIALS: client_credentials_token_handler,
    GrantType.AUTHORIZATION_CODE: not_implemented_token_handler
}