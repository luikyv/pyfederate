import typing
from fastapi import status

from ..utils import constants, schemas, exceptions
from ..utils.constants import GrantType

def validate_client(client: schemas.Client, client_secret: str, requested_scopes: typing.List[str]) -> None:
    if(not client.is_authenticated(client_secret=client_secret)):
        raise exceptions.HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            error=constants.ErrorCode.ACCESS_DENIED,
            error_description="invalid credentials"
        )
    
    # Check if the scopes requested are available to the client
    if(not client.are_scopes_allowed(requested_scopes=requested_scopes)):
        raise exceptions.HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            error=constants.ErrorCode.ACCESS_DENIED,
            error_description="the client does not have access to the required scopes"
        )

def client_credentials_token_handler(
    client: schemas.Client,
    requested_scopes: typing.List[str]
) -> schemas.TokenResponse:
    
    token_model: schemas.TokenModel = client.token_model
    token: schemas.BearerToken = token_model.generate_token(
        client_id=client.id,
        subject=client.id,
        scopes=client.scopes if requested_scopes else requested_scopes
    )
    return schemas.TokenResponse(
        access_token=token.token,
        expires_in=token_model.expires_in
    )

def not_implemented_token_handler(
    client: schemas.Client,
    requested_scopes: typing.List[str]
) -> schemas.TokenResponse:
    raise exceptions.HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            error=constants.ErrorCode.ACCESS_DENIED,
            error_description="Problem"
        )

grant_handlers: typing.Dict[
    GrantType,
    typing.Callable[
        [schemas.Client, typing.List[str]], schemas.TokenResponse
    ]
] = {
    GrantType.CLIENT_CREDENTIALS: client_credentials_token_handler,
    GrantType.AUTHORIZATION_CODE: not_implemented_token_handler
}