from typing import Dict, Any
import jwt
import pytest
from fastapi.exceptions import RequestValidationError

from tests import conftest
from auth_server.utils import schemas, constants, exceptions


@pytest.fixture
def expected_payload() -> Dict[str, Any]:
    return {
        "sub": conftest.USER_ID,
        "iss": conftest.ISSUER,
        "iat": conftest.timestamp_now,
        "exp": conftest.timestamp_now + conftest.TOKEN_EXPIRATION,
        "client_id": conftest.CLIENT_ID,
        "jti": conftest.TOKEN_ID,
        "scope": " ".join(conftest.SCOPES),
    }


class TestTokenInfo:
    def test_to_jwt_payload(
        self, token_info: schemas.TokenInfo, expected_payload: Dict[str, Any]
    ) -> None:
        """Test if the jwt payload is correct"""

        token_info.additional_info = {
            # The additional info should not be capable of overwriting the standard fields
            "sub": "new_user@email.com",
            "claim": "value",
        }
        expected_payload["claim"] = "value"

        assert (
            token_info.to_jwt_payload() == expected_payload
        ), "The JWT payload is wrong"


class TestJWTTokenModel:
    def test_generate_token(
        self,
        jwt_token_model: schemas.JWTTokenModel,
        token_info: schemas.TokenInfo,
        expected_payload: Dict[str, Any],
    ) -> None:
        """Test if the jwt payload generated is correct"""
        jwt_token: str = jwt_token_model.generate_token(token_info=token_info)

        assert (
            jwt.decode(
                jwt_token,
                algorithms=[jwt_token_model.signing_algorithm.value],
                key=jwt_token_model.key,
            )
            == expected_payload
        ), "The decoded JWT payload is wrong"


class TestTokenModelIn:
    def test_jwt_tokens_must_have_key_id(self) -> None:
        """Test that JWT token models must have a key ID"""

        with pytest.raises(RequestValidationError):
            schemas.TokenModelIn(
                id="",
                issuer="",
                expires_in=0,
                is_refreshable=False,
                token_type=constants.TokenType.JWT,
                key_id=None,
            )


class TestClientUpsert:
    def test_setup_secret_authentication(self) -> None:
        """
        Test that client to be upserted that authenticate with secret
        have the secret generated automatically.
        """

        client_upsert = schemas.ClientUpsert(
            id="",
            authn_method=constants.ClientAuthnMethod.CLIENT_SECRET_POST,
            redirect_uris=[],
            response_types=[],
            grant_types=[],
            scopes=[],
            is_pkce_required=False,
            token_model_id="",
        )
        assert client_upsert.secret is not None


class TestClient:
    def test_is_authenticated_by_secret(
        self, secret_authenticated_client: schemas.Client
    ) -> None:

        assert secret_authenticated_client.is_authenticated_by_secret(
            client_secret=conftest.CLIENT_SECRET
        ), "The client secret should be valid"
        assert not secret_authenticated_client.is_authenticated_by_secret(
            client_secret="invalid_secret"
        ), "The client secret should not be valid"

    def test_are_scopes_allowed(
        self, secret_authenticated_client: schemas.Client
    ) -> None:
        assert secret_authenticated_client.are_scopes_allowed(
            conftest.SCOPES
        ), "The scopes should be allowed"
        assert not secret_authenticated_client.are_scopes_allowed(
            ["invalid_scope"]
        ), "The scopes should not be allowed"

    def test_owns_redirect_uri(
        self, secret_authenticated_client: schemas.Client
    ) -> None:
        assert secret_authenticated_client.owns_redirect_uri(
            conftest.REDIRECT_URI
        ), "The client owns the redirect uri"
        assert not secret_authenticated_client.owns_redirect_uri(
            "invalid_redirect_uri"
        ), "The client doesn't own the redirect uri"

    def test_are_response_types_allowed(
        self, secret_authenticated_client: schemas.Client
    ) -> None:
        secret_authenticated_client.response_types = [constants.ResponseType.CODE]

        assert secret_authenticated_client.are_response_types_allowed(
            [constants.ResponseType.CODE]
        ), "The response types are allowed"
        assert not secret_authenticated_client.are_response_types_allowed(
            [constants.ResponseType.ID_TOKEN]
        ), "The response types are not allowed"

    def test_is_grant_type_allowed(
        self, secret_authenticated_client: schemas.Client
    ) -> None:
        secret_authenticated_client.grant_types = [
            constants.GrantType.AUTHORIZATION_CODE
        ]

        assert secret_authenticated_client.is_grant_type_allowed(
            grant_type=constants.GrantType.AUTHORIZATION_CODE
        ), "The grant type should be allowed"
        assert not secret_authenticated_client.is_grant_type_allowed(
            grant_type=constants.GrantType.CLIENT_CREDENTIALS
        ), "The grant type should not be allowed"


class TestClientIn:
    def test_only_authz_code_has_response_types(
        self, client_in: schemas.ClientIn
    ) -> None:
        with pytest.raises(RequestValidationError):
            schemas.ClientIn(
                **{
                    **dict(client_in),
                    "grant_types": [constants.GrantType.CLIENT_CREDENTIALS],
                    "response_types": [constants.ResponseType.CODE],
                }
            )

    def test_client_credentials_authn_method(self, client_in: schemas.ClientIn) -> None:
        with pytest.raises(RequestValidationError):
            schemas.ClientIn(
                **{
                    **dict(client_in),
                    "grant_types": [
                        constants.GrantType.AUTHORIZATION_CODE,
                        constants.GrantType.CLIENT_CREDENTIALS,
                    ],
                    "authn_method": constants.ClientAuthnMethod.NONE,
                }
            )

    def test_refresh_token_authn_method(self, client_in: schemas.ClientIn) -> None:
        with pytest.raises(RequestValidationError):
            schemas.ClientIn(
                **{
                    **dict(client_in),
                    "grant_types": [
                        constants.GrantType.AUTHORIZATION_CODE,
                        constants.GrantType.REFRESH_TOKEN,
                    ],
                    "authn_method": constants.ClientAuthnMethod.NONE,
                }
            )

    def test_client_without_authn_method_must_require_pkce(
        self, client_in: schemas.ClientIn
    ) -> None:
        with pytest.raises(RequestValidationError):
            schemas.ClientIn(
                **{
                    **dict(client_in),
                    "grant_types": [constants.GrantType.AUTHORIZATION_CODE],
                    "authn_method": constants.ClientAuthnMethod.NONE,
                    "is_pkce_required": False,
                }
            )
