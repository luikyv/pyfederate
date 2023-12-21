from pydantic import BaseModel, model_validator, Field
from dataclasses import dataclass, field
from fastapi.exceptions import RequestValidationError
from typing import Any, List, Dict, Optional, Callable, Awaitable
import bcrypt
import jwt
from datetime import datetime
from abc import ABC, abstractmethod
from fastapi import Request, Response, status
from fastapi.responses import RedirectResponse

from . import constants, exceptions
from .constants import TokenClaim, ErrorCode, GrantType, ClientAuthnMethod
from . import tools

######################################## Token ########################################


@dataclass
class TokenInfo:
    subject: str
    issuer: str
    issued_at: int
    expiration: int
    client_id: str
    scopes: List[str]
    id: str = field(default_factory=tools.generate_uuid)
    additional_info: Dict[str, str] = field(default_factory=dict)

    def to_jwt_payload(self) -> Dict[str, Any]:
        payload = {
            TokenClaim.JWT_ID.value: self.id,
            TokenClaim.SUBJECT.value: self.subject,
            TokenClaim.ISSUER.value: self.issuer,
            TokenClaim.ISSUED_AT.value: self.issued_at,
            TokenClaim.EXPIRATION.value: self.expiration,
            TokenClaim.CLIENT_ID.value: self.client_id,
            TokenClaim.SCOPE.value: " ".join(self.scopes),
        }

        # Merge the two dicts and do not allow the additional_info to override values in the payload
        return self.additional_info | payload


class BaseTokenModel(BaseModel):
    id: str
    issuer: str
    expires_in: int
    is_refreshable: bool
    refresh_lifetime_secs: int = Field(default=0)


class TokenModel(BaseTokenModel, ABC):
    @abstractmethod
    def generate_token(self, token_info: TokenInfo) -> str:
        pass

    @abstractmethod
    def to_output(self) -> "TokenModelOut":
        pass


class JWTTokenModel(TokenModel):
    key_id: str
    key: str
    signing_algorithm: constants.SigningAlgorithm

    def generate_token(self, token_info: TokenInfo) -> str:

        return jwt.encode(
            payload=token_info.to_jwt_payload(),
            key=self.key,
            algorithm=self.signing_algorithm.value,
        )

    def to_output(self) -> "TokenModelOut":

        return TokenModelOut(
            id=self.id,
            issuer=self.issuer,
            expires_in=self.expires_in,
            token_type=constants.TokenType.JWT,
            is_refreshable=self.is_refreshable,
            key_id=self.key_id,
            signing_algorithm=self.signing_algorithm,
        )


class TokenModelUpsert(BaseTokenModel):
    token_type: constants.TokenType
    key_id: str | None


#################### API Models ####################


class TokenModelIn(BaseTokenModel):
    token_type: constants.TokenType
    key_id: constants.JWK_IDS_LITERAL | None

    @model_validator(mode="after")  # type: ignore
    def jwt_tokens_must_have_key_id(self: "TokenModelIn") -> "TokenModelIn":
        if self.token_type == constants.TokenType.JWT and self.key_id is None:
            raise RequestValidationError("jwt model must have an key id")
        return self

    def to_upsert(self) -> TokenModelUpsert:
        return TokenModelUpsert(
            id=self.id,
            issuer=self.issuer,
            expires_in=self.expires_in,
            is_refreshable=self.is_refreshable,
            token_type=self.token_type,
            key_id=self.key_id,
        )


class TokenModelOut(BaseTokenModel):
    token_type: constants.TokenType
    key_id: str | None
    signing_algorithm: constants.SigningAlgorithm | None


######################################## Scope ########################################


class Scope(BaseModel):
    name: str
    description: str

    def to_output(self) -> "ScopeOut":
        return ScopeOut(name=self.name, description=self.description)


class ScopeUpsert(Scope):
    pass


#################### API Models ####################


class ScopeIn(Scope):
    def to_upsert(self) -> ScopeUpsert:
        return ScopeUpsert(name=self.name, description=self.description)


class ScopeOut(Scope):
    pass


######################################## Client ########################################


class AuthnMethod(BaseModel):
    pass


class SecretAuthnMethod(AuthnMethod):
    secret: str


class PrivateKeyJWTAuthnMethod(AuthnMethod):
    key: str
    signing_alg: str


class ClientBase(BaseModel):
    id: str
    authn_method: constants.ClientAuthnMethod
    redirect_uris: List[str]
    response_types: List[constants.ResponseType]
    grant_types: List[constants.GrantType]
    scopes: List[str]
    is_pkce_required: bool
    extra_params: Dict[str, str] = Field(default_factory=dict)


class ClientUpsert(ClientBase):
    token_model_id: str
    secret: str | None = Field(default=None, init_var=False)
    hashed_secret: str | None = Field(default=None, init_var=False)

    @model_validator(mode="after")  # type: ignore
    def setup_secret_authentication(self) -> "ClientUpsert":
        """Set up secret authentication"""
        if self.authn_method == ClientAuthnMethod.CLIENT_SECRET_POST:
            self.secret = tools.generate_client_secret()
            self.hashed_secret = tools.hash_secret(secret=self.secret)

        return self


class Client(ClientBase):
    token_model: TokenModel
    secret: str | None = None
    hashed_secret: str | None

    def to_output(self) -> "ClientOut":
        return ClientOut(**{**dict(self), "token_model_id": self.token_model.id})

    def is_authenticated_by_secret(self, client_secret: str) -> bool:
        if self.hashed_secret is None:
            return False

        return bcrypt.checkpw(
            password=client_secret.encode(constants.SECRET_ENCODING),
            hashed_password=self.hashed_secret.encode(constants.SECRET_ENCODING),
        )

    def are_scopes_allowed(self, requested_scopes: List[str]) -> bool:
        return set(requested_scopes).issubset(set(self.scopes))

    def owns_redirect_uri(self, redirect_uri: str) -> bool:
        return redirect_uri in self.redirect_uris

    def are_response_types_allowed(
        self, response_types: List[constants.ResponseType]
    ) -> bool:
        return all([rt in self.response_types for rt in response_types])

    def is_grant_type_allowed(self, grant_type: constants.GrantType) -> bool:
        return grant_type in self.grant_types


#################### API Models ####################


class ClientIn(ClientBase):
    id: str = Field(default_factory=tools.generate_client_id)
    token_model_id: str

    def to_upsert(self) -> ClientUpsert:
        return ClientUpsert(**dict(self))

    @model_validator(mode="after")  # type: ignore
    def only_authz_code_has_response_types(self) -> "ClientIn":
        """Response types are only allowed for the authorization code grant type"""

        if (
            constants.GrantType.AUTHORIZATION_CODE not in self.grant_types
            and self.response_types
        ):
            raise RequestValidationError(
                "Response types are only allowed to the authorization code grant"
            )
        return self

    @model_validator(mode="after")  # type: ignore
    def client_credentials_authn_method(self) -> "ClientIn":
        """Clients allowed to perform client credentials must have an authn method"""
        if (
            constants.GrantType.CLIENT_CREDENTIALS in self.grant_types
            and self.authn_method == ClientAuthnMethod.NONE
        ):
            raise RequestValidationError(
                "An authentication method must be provided for the client credentials grant"
            )
        return self

    @model_validator(mode="after")  # type: ignore
    def refresh_token_authn_method(self) -> "ClientIn":
        """Clients allowed to perform refresh token must have an authn method"""
        if (
            constants.GrantType.REFRESH_TOKEN in self.grant_types
            and self.authn_method == ClientAuthnMethod.NONE
        ):
            raise RequestValidationError(
                "An authentication method must be provided for the refresh token grant"
            )
        return self

    @model_validator(mode="after")  # type: ignore
    def client_without_authn_method_must_require_pkce(self) -> "ClientIn":

        if self.authn_method == ClientAuthnMethod.NONE and not self.is_pkce_required:
            raise RequestValidationError(
                "Clients without an authentication method must require PCKE"
            )
        return self


class ClientOut(ClientBase):
    token_model_id: str
    secret: str | None = None


######################################## OAuth ########################################

#################### Token Endpoint ####################


@dataclass
class GrantContext:
    grant_type: constants.GrantType
    client: Client
    token_model: TokenModel
    requested_scopes: List[str]
    redirect_uri: str | None
    refresh_token: str | None
    authz_code: str | None
    code_verifier: str | None
    correlation_id: constants.CORRELATION_ID_HEADER_TYPE


class TokenResponse(BaseModel):
    access_token: str
    expires_in: int
    token_type: str = Field(default=constants.BEARER_TOKEN_TYPE)
    refresh_token: str | None = None
    scope: str | None = None


#################### Pushed Authorization Request Endpoint ####################


class PARResponse(BaseModel):
    request_uri: str
    expires_in: int


#################### Authorization Endpoint ####################


@dataclass
class AuthorizeContext:
    client: Client
    requested_scopes: List[str]
    response_types: List[constants.ResponseType]
    redirect_uri: str
    code_challenge: str | None
    code_challenge_method: constants.CodeChallengeMethod


######################################## Session ########################################


@dataclass
class AuthnSession:
    callback_id: str | None
    tracking_id: str
    correlation_id: str
    client_id: str
    redirect_uri: str
    response_types: List[constants.ResponseType]
    requested_scopes: List[str]
    state: str
    auth_policy_id: str
    next_authn_step_id: str
    user_id: str | None
    authz_code: str | None
    authz_code_creation_timestamp: int | None
    code_challenge: str | None
    request_uri: str | None
    params: Dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=tools.generate_session_id)


@dataclass
class TokenSession:
    token_id: str
    refresh_token: str | None
    client_id: str
    token_model_id: str
    token_info: TokenInfo
    created_at: datetime


######################################## Auth Policy ########################################


AUTHN_POLICIES: Dict[str, "AuthnPolicy"] = {}
AUTHN_STEPS: Dict[str, "AuthnStep"] = {}


@dataclass
class AuthnStepResult(ABC):
    status: constants.AuthnStatus

    @abstractmethod
    def get_response(self, session: AuthnSession) -> Response:
        pass


@dataclass
class AuthnStepInProgressResult(AuthnStepResult):
    response: Response
    status: constants.AuthnStatus = field(
        default=constants.AuthnStatus.IN_PROGRESS, init=False
    )

    def get_response(self, session: AuthnSession) -> Response:
        return self.response


@dataclass
class AuthnStepFailureResult(AuthnStepResult):
    error_description: str | None = None
    status: constants.AuthnStatus = field(
        default=constants.AuthnStatus.FAILURE, init=False
    )

    def get_response(self, session: AuthnSession) -> Response:
        raise exceptions.RedirectResponseException(
            error=ErrorCode.ACCESS_DENIED,
            error_description=self.error_description
            if self.error_description
            else "access denied",
            redirect_uri=session.redirect_uri,
            state=session.state,
        )


@dataclass
class AuthnStepSuccessResult(AuthnStepResult):
    status: constants.AuthnStatus = field(
        default=constants.AuthnStatus.SUCCESS, init=False
    )

    def get_response(self, session: AuthnSession) -> Response:

        if session.authz_code is None:
            raise RuntimeError("The authorization code cannot be None")

        return RedirectResponse(
            url=tools.prepare_redirect_url(
                url=session.redirect_uri,
                params={
                    "code": session.authz_code,
                    "state": session.state,
                },
            ),
            status_code=status.HTTP_302_FOUND,
        )


@dataclass
class AuthnStep:
    id: str
    authn_func: Callable[
        [AuthnSession, Request], AuthnStepResult | Awaitable[AuthnStepResult]
    ]
    success_next_step: Optional["AuthnStep"]
    failure_next_step: Optional["AuthnStep"]

    def __post_init__(self) -> None:
        # Make sure the step id is unique
        if self.id in AUTHN_STEPS:
            raise RuntimeError(
                f"An authentication step with ID: {self.id} already exists"
            )
        AUTHN_STEPS[self.id] = self


async def default_failure_authn_func(
    session: AuthnSession, request: Request
) -> AuthnStepResult:
    return AuthnStepFailureResult(error_description="access denied")


# Step that always returns failure
default_failure_step = AuthnStep(
    id="default_failure_step_42",
    authn_func=default_failure_authn_func,
    success_next_step=None,
    failure_next_step=None,
)


@dataclass
class AuthnPolicy:
    id: str
    is_available: Callable[[Client, Request], bool]
    first_step: AuthnStep
    get_extra_token_claims: Callable[[AuthnSession], Dict[str, str]] | None = None

    def __post_init__(self) -> None:
        # Make sure the policy id is unique
        if self.id in AUTHN_POLICIES:
            raise RuntimeError(
                f"An authentication policy with ID: {self.id} already exists"
            )
        AUTHN_POLICIES[self.id] = self
