from typing import Dict, Any
import pytest
from unittest.mock import Mock, patch, MagicMock
import jwt

from tests import conftest
from auth_server.utils import constants, schemas, helpers, exceptions

#################### Test helpers.get_authenticated_client ####################


@pytest.mark.asyncio
@patch("auth_server.utils.helpers.manager")
async def test_get_authenticated_client_without_authentication(
    mocked_manager: MagicMock,
    no_authentication_client: schemas.Client
) -> None:

    mocked_manager.client_manager.get_client = Mock(
        side_effect=lambda *args, **kwargs: conftest.async_return(o=no_authentication_client))

    authenticated_client: schemas.Client = await helpers.get_authenticated_client(
        client_id=conftest.CLIENT_ID,
        client_secret=None
    )

    assert authenticated_client.id == conftest.CLIENT_ID


@pytest.mark.asyncio
@patch("auth_server.utils.helpers.manager")
async def test_get_authenticated_client_no_secret_provided(
    mocked_manager: MagicMock,
    secret_authenticated_client: schemas.Client,
) -> None:
    """
    Verify that not providing a secret for a client authenticates with secret raises an exception
    """

    mocked_manager.client_manager.get_client = Mock(
        side_effect=lambda *args, **kwargs: conftest.async_return(o=secret_authenticated_client))

    with pytest.raises(exceptions.ClientIsNotAuthenticatedException):
        _: schemas.Client = await helpers.get_authenticated_client(
            client_id=conftest.CLIENT_ID,
            client_secret=None
        )


@pytest.mark.asyncio
@patch("auth_server.utils.helpers.manager")
async def test_get_authenticated_client_invalid_secret(
    mocked_manager: MagicMock,
    secret_authenticated_client: schemas.Client
) -> None:
    """
    Verify that providing the wrong secret for a client authenticates with secret raises an exception
    """

    mocked_manager.client_manager.get_client = Mock(
        side_effect=lambda *args, **kwargs: conftest.async_return(o=secret_authenticated_client))

    with pytest.raises(exceptions.ClientIsNotAuthenticatedException):
        _: schemas.Client = await helpers.get_authenticated_client(
            client_id=conftest.CLIENT_ID,
            client_secret="invalid_secret"
        )


@pytest.mark.asyncio
@patch("auth_server.utils.helpers.manager")
async def test_get_authenticated_client_valid_secret(
    mocked_manager: MagicMock,
    secret_authenticated_client: schemas.Client
) -> None:

    mocked_manager.client_manager.get_client = Mock(
        side_effect=lambda *args, **kwargs: conftest.async_return(o=secret_authenticated_client))

    authenticated_client: schemas.Client = await helpers.get_authenticated_client(
        client_id=conftest.CLIENT_ID,
        client_secret=conftest.CLIENT_SECRET
    )

    assert authenticated_client.id == conftest.CLIENT_ID


#################### Test helpers.get_response_types ####################

def test_get_response_types_with_invalid_response_type() -> None:
    response_type = "invalid_response_type"
    with pytest.raises(ValueError):
        helpers.get_response_types(response_type=response_type)


def test_get_response_types_with_valid_response_types() -> None:
    response_types = [constants.ResponseType.CODE,
                      constants.ResponseType.ID_TOKEN]
    assert response_types == helpers.get_response_types(
        response_type=" ".join([rt.value for rt in response_types]))


#################### Test helpers.get_scopes ####################

def test_get_scopes() -> None:

    scopes = ["scope1", "scope2"]

    assert scopes == helpers.get_scopes(scope_string=" ".join(scopes))
    assert [] == helpers.get_scopes(scope_string="")
    assert [] == helpers.get_scopes(scope_string=None)


#################### Test helpers.client_credentials_token_handler ####################

@pytest.mark.asyncio
async def test_client_credentials_token_handler_grant_not_allowed(
    client_credentials_grant_context: schemas.GrantContext
) -> None:

    client_credentials_grant_context.client.grant_types = []

    with pytest.raises(exceptions.GrantTypeNotAllowedException):
        await helpers.client_credentials_token_handler(grant_context=client_credentials_grant_context)


@pytest.mark.asyncio
async def test_client_credentials_token_handler_no_authentication_client(
    client_credentials_grant_context: schemas.GrantContext,
) -> None:

    client_credentials_grant_context.client.authn_method = constants.ClientAuthnMethod.NONE

    with pytest.raises(exceptions.ClientIsNotAuthenticatedException):
        await helpers.client_credentials_token_handler(grant_context=client_credentials_grant_context)


@pytest.mark.asyncio
async def test_client_credentials_token_handler_scope_not_allowed(
    client_credentials_grant_context: schemas.GrantContext
) -> None:

    client_credentials_grant_context.requested_scopes = ["scope_not_allowed"]

    with pytest.raises(exceptions.RequestedScopesAreNotAllowedException):
        await helpers.client_credentials_token_handler(grant_context=client_credentials_grant_context)


@pytest.mark.asyncio
async def test_client_credentials_token_handler_generate_jwt_token(
    client_credentials_grant_context: schemas.GrantContext
) -> None:

    token_response: schemas.TokenResponse = await helpers.client_credentials_token_handler(grant_context=client_credentials_grant_context)
    payload: Dict[str, Any] = jwt.decode(token_response.access_token,
                                         key=conftest.HMAC_SIGNING_KEY,
                                         algorithms=[conftest.SIGNING_ALGORITHM.value])

    assert payload["sub"] == client_credentials_grant_context.client.id
    assert payload["scope"] == " ".join(
        client_credentials_grant_context.client.scopes)


#################### Test helpers.create_token_session ####################

@pytest.mark.asyncio
@patch("auth_server.utils.helpers.manager")
async def test_create_token_session(
    mocked_manager: MagicMock,
    authorization_code_grant_context: schemas.GrantContext,
    authentication_session: schemas.AuthnSession,
    token_info: schemas.TokenInfo
) -> None:

    mocked_manager.session_manager.create_token_session = Mock(
        side_effect=lambda *args, **kwargs: conftest.async_return(o=None))

    token_session: schemas.TokenSession = await helpers.create_token_session(
        authz_code_context=schemas.AuthorizationCodeGrantContext(
            **dict(authorization_code_grant_context),
            session=authentication_session
        ),
        token_info=token_info
    )

    mocked_manager.session_manager.create_token_session.assert_called_once()
    assert token_session.token_id == token_info.id


#################### Test helpers.authorization_code_token_handler ####################


@pytest.mark.asyncio
async def test_authorization_code_token_handler_no_code_provided(
    authorization_code_grant_context: schemas.GrantContext,
) -> None:

    authorization_code_grant_context.authz_code = None

    with pytest.raises(exceptions.InvalidAuthorizationCodeException):
        await helpers.authorization_code_token_handler(
            grant_context=authorization_code_grant_context
        )


@pytest.mark.asyncio
@patch("auth_server.utils.helpers.manager")
async def test_authorization_code_token_handler_jwt_response(
    mocked_manager: MagicMock,
    authorization_code_grant_context: schemas.GrantContext,
    authentication_session: schemas.AuthnSession,
    autentication_policy: schemas.AuthnPolicy
) -> None:

    # Arrange
    mocked_manager.session_manager.get_session_by_authz_code = Mock(
        side_effect=lambda *args, **kwargs: conftest.async_return(o=authentication_session))
    mocked_manager.session_manager.delete_session = Mock(
        side_effect=lambda *args, **kwargs: conftest.async_return(o=None))
    mocked_manager.session_manager.create_token_session = Mock(
        side_effect=lambda *args, **kwargs: conftest.async_return(o=None))

    # Act
    token_response: schemas.TokenResponse = await helpers.authorization_code_token_handler(
        grant_context=authorization_code_grant_context
    )

    # Assert
    mocked_manager.session_manager.delete_session.assert_called_once()
    assert token_response.access_token
    payload: Dict[str, Any] = jwt.decode(token_response.access_token,
                                         key=conftest.HMAC_SIGNING_KEY,
                                         algorithms=[conftest.SIGNING_ALGORITHM.value])
    assert payload["sub"] == authentication_session.user_id
    assert payload["scope"] == " ".join(
        authentication_session.requested_scopes)
