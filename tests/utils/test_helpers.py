from typing import Dict, Any
import pytest
from unittest.mock import Mock, patch
import asyncio
import jwt

from tests import conftest
from auth_server.utils import constants, schemas, helpers, exceptions
from auth_server.auth_manager import manager

#################### Test helpers.get_authenticated_client ####################


@pytest.mark.asyncio
async def test_get_authenticated_client_without_authentication(no_authentication_client: schemas.Client) -> None:

    manager._client_manager = Mock()
    manager.client_manager.get_client = Mock(
        side_effect=lambda *args, **kwargs: conftest.async_return(o=no_authentication_client))

    authenticated_client: schemas.Client = await helpers.get_authenticated_client(
        client_id=conftest.CLIENT_ID,
        client_secret=None
    )

    assert authenticated_client.id == conftest.CLIENT_ID


@pytest.mark.asyncio
async def test_get_authenticated_client_no_secret_provided(secret_authenticated_client: schemas.Client) -> None:
    """
    Verify that not providing a secret for a client authenticates with secret raises an exception
    """

    manager._client_manager = Mock()
    manager.client_manager.get_client = Mock(
        side_effect=lambda *args, **kwargs: conftest.async_return(o=secret_authenticated_client))

    with pytest.raises(exceptions.ClientIsNotAuthenticatedException):
        _: schemas.Client = await helpers.get_authenticated_client(
            client_id=conftest.CLIENT_ID,
            client_secret=None
        )


@pytest.mark.asyncio
async def test_get_authenticated_client_invalid_secret(secret_authenticated_client: schemas.Client) -> None:
    """
    Verify that providing the wrong secret for a client authenticates with secret raises an exception
    """

    manager._client_manager = Mock()
    manager.client_manager.get_client = Mock(
        side_effect=lambda *args, **kwargs: conftest.async_return(o=secret_authenticated_client))

    with pytest.raises(exceptions.ClientIsNotAuthenticatedException):
        _: schemas.Client = await helpers.get_authenticated_client(
            client_id=conftest.CLIENT_ID,
            client_secret="invalid_secret"
        )


@pytest.mark.asyncio
async def test_get_authenticated_client_valid_secret(secret_authenticated_client: schemas.Client) -> None:

    manager._client_manager = Mock()
    manager.client_manager.get_client = Mock(
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
    secret_authenticated_client: schemas.Client
) -> None:

    secret_authenticated_client.grant_types = []
    grant_context = schemas.GrantContext(
        grant_type=constants.GrantType.CLIENT_CREDENTIALS,
        client=secret_authenticated_client,
        token_model=secret_authenticated_client.token_model,
        requested_scopes=[],
        redirect_uri=None,
        refresh_token=None,
        authz_code=None,
        code_verifier=None,
        correlation_id=None
    )

    with pytest.raises(exceptions.GrantTypeNotAllowedException):
        await helpers.client_credentials_token_handler(grant_context=grant_context)


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
                                         key=conftest.jwt_token_model.key,
                                         algorithms=[conftest.jwt_token_model.signing_algorithm.value])

    assert payload["sub"] == client_credentials_grant_context.client.id
    assert payload["scope"] == " ".join(
        client_credentials_grant_context.client.scopes)
