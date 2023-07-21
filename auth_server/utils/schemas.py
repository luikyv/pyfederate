from pydantic import BaseModel, field_validator, model_validator, Field
from dataclasses import dataclass, field, asdict
from typing import Any, List, Dict, Optional, Callable, Awaitable
import bcrypt
import jwt
import time
from fastapi import Request, Response, status
from fastapi.responses import RedirectResponse

from . import constants, exceptions
from .constants import TokenClaim, ErrorCode, GrantType, ClientAuthnMethod
from .import tools

######################################## Token ########################################


@dataclass
class TokenInfo():
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
            **self.additional_info,
            TokenClaim.JWT_ID.value: self.id,
            TokenClaim.SUBJECT.value: self.subject,
            TokenClaim.ISSUER.value: self.issuer,
            TokenClaim.ISSUED_AT.value: self.issued_at,
            TokenClaim.EXPIRATION.value: self.expiration,
            TokenClaim.CLIENT_ID.value: self.client_id,
            TokenClaim.SCOPE.value: " ".join(self.scopes)
        }

        return payload


@dataclass
class BearerToken:
    id: str
    info: TokenInfo
    token: str


class TokenModel(BaseModel):
    id: str
    issuer: str
    expires_in: int

    def generate_token(
        self,
        client_id: str,
        subject: str,
        scopes: List[str],
        additional_claims: Dict[str, str]
    ) -> BearerToken:
        raise NotImplementedError()

    def to_output(self) -> "TokenModelOut":
        raise NotImplementedError()


class TokenModelUpsert(TokenModel):
    token_type: constants.TokenType
    key_id: str | None


class JWTTokenModel(TokenModel):
    key_id: str
    key: str
    signing_algorithm: constants.SigningAlgorithm

    def generate_token(
        self,
        client_id: str,
        subject: str,
        scopes: List[str],
        additional_claims: Dict[str, str]
    ) -> BearerToken:

        timestamp_now = tools.get_timestamp_now()
        token_info = TokenInfo(
            subject=subject,
            issuer=self.issuer,
            issued_at=timestamp_now,
            expiration=timestamp_now + self.expires_in,
            client_id=client_id,
            scopes=scopes,
            additional_info=additional_claims
        )

        return BearerToken(
            id=token_info.id,
            info=token_info,
            token=jwt.encode(
                payload=token_info.to_jwt_payload(),
                key=self.key,
                algorithm=self.signing_algorithm.value
            )
        )

    def to_output(self) -> "TokenModelOut":

        return TokenModelOut(
            id=self.id,
            issuer=self.issuer,
            expires_in=self.expires_in,
            token_type=constants.TokenType.JWT,
            key_id=self.key_id,
            signing_algorithm=self.signing_algorithm
        )

#################### API Models ####################


class TokenModelIn(TokenModel):
    token_type: constants.TokenType
    key_id: constants.JWK_IDS_LITERAL | None

    @model_validator(mode="after")
    def jwt_tokens_must_have_key_id(self: "TokenModelIn") -> "TokenModelIn":
        if self.token_type == constants.TokenType.JWT and self.key_id is None:
            raise exceptions.JWTModelMustHaveKeyIDException()
        return self

    def to_upsert(self) -> TokenModelUpsert:
        return TokenModelUpsert(
            id=self.id,
            issuer=self.issuer,
            expires_in=self.expires_in,
            token_type=self.token_type,
            key_id=self.key_id,
        )


class TokenModelOut(TokenModel):
    token_type: constants.TokenType
    key_id: str | None
    signing_algorithm: constants.SigningAlgorithm | None

######################################## Scope ########################################


class Scope(BaseModel):
    name: str
    description: str

    def to_output(self) -> "ScopeOut":
        return ScopeOut(
            name=self.name,
            description=self.description
        )


class ScopeUpsert(Scope):
    pass

#################### API Models ####################


@dataclass
class ScopeIn(Scope):

    def to_upsert(self) -> ScopeUpsert:
        return ScopeUpsert(
            name=self.name,
            description=self.description
        )


@dataclass
class ScopeOut(Scope):
    pass

######################################## Client ########################################


class ClientBase(BaseModel):
    id: str
    authn_method: constants.ClientAuthnMethod
    redirect_uris: List[str]
    response_types: List[constants.ResponseType]
    grant_types: List[constants.GrantType]
    scopes: List[str]
    is_pcke_required: bool
    extra_params: Dict[str, str] = Field(default_factory=dict)


class ClientUpsert(ClientBase):
    token_model_id: str
    secret: str | None = None

    @model_validator(mode="after")
    def setup_secret_authentication(self) -> "ClientUpsert":
        """Set up secret authentication"""
        if self.authn_method == ClientAuthnMethod.SECRET:
            self.secret = tools.generate_client_secret()

        return self


class Client(ClientBase):
    token_model: TokenModel
    secret: str | None = None
    hashed_secret: str | None

    def to_output(self) -> "ClientOut":
        return ClientOut(**self.model_dump())

    def is_authenticated_by_secret(self, client_secret: str) -> bool:
        if (self.hashed_secret is None):
            return False

        return bcrypt.checkpw(
            password=client_secret.encode(constants.SECRET_ENCODING),
            hashed_password=self.hashed_secret.encode(
                constants.SECRET_ENCODING)
        )

    def are_scopes_allowed(self, requested_scopes: List[str]) -> bool:
        return set(requested_scopes).issubset(set(self.scopes))

    def owns_redirect_uri(self, redirect_uri: str) -> bool:
        return redirect_uri in self.redirect_uris

    def is_response_type_allowed(self, response_type: constants.ResponseType) -> bool:
        return response_type in self.response_types

    def is_grant_type_allowed(self, grant_type: constants.GrantType) -> bool:
        return grant_type in self.grant_types

#################### API Models ####################


class ClientIn(ClientBase):
    id: str = Field(default_factory=tools.generate_client_id)
    token_model_id: str

    def to_upsert(self) -> ClientUpsert:
        return ClientUpsert(**self.model_dump())

    @model_validator(mode="after")
    def only_authz_code_has_response_types(self) -> "ClientIn":
        """Response type are only allowed for the authorization code grant type"""
        if (constants.GrantType.AUTHORIZATION_CODE not in self.grant_types
           and self.response_types):
            raise ValueError(
                "Response types are only allowed to the authorization code grant"
            )
        return self

    @model_validator(mode="after")
    def client_credentials_authn_method(self) -> "ClientIn":
        """Clients allowed to perform client credentials must have an authn method"""
        if (constants.GrantType.CLIENT_CREDENTIALS in self.grant_types
                and self.authn_method == ClientAuthnMethod.NONE):
            raise ValueError(
                "An authentication method must be provided for the client credentials grant"
            )
        return self

    @model_validator(mode="after")
    def client_without_authn_method_must_require_pcke(self) -> "ClientIn":

        if (self.authn_method == ClientAuthnMethod.NONE and not self.is_pcke_required):
            raise ValueError(
                "Clients without an authentication method must require PCKE"
            )
        return self


class ClientOut(ClientBase):
    token_model_id: str
    secret: str | None = None

######################################## OAuth ########################################

#################### /token ####################


class GrantContext(BaseModel):
    grant_type: constants.GrantType
    client: Client
    token_model: TokenModel
    client_secret: str | None
    requested_scopes: List[str]
    redirect_uri: str | None
    authz_code: str | None
    code_verifier: str | None
    correlation_id: constants.CORRELATION_ID_HEADER_TYPE


class CommonValidationsGrantContext(GrantContext):
    """Class to hold common grant context validations"""

    @model_validator(mode="after")
    def grant_type_is_allowed(self) -> "CommonValidationsGrantContext":
        if (not self.client.is_grant_type_allowed(grant_type=self.grant_type)):
            raise exceptions.GrantTypeNotAllowed()
        return self

    @model_validator(mode="after")
    def client_is_authenticated(self) -> "CommonValidationsGrantContext":
        if (self.client.authn_method == constants.ClientAuthnMethod.SECRET):
            if (self.client_secret is None or not self.client.is_authenticated_by_secret(client_secret=self.client_secret)):
                raise exceptions.ClientIsNotAuthenticated()
        return self


class ClientCredentialsContext(CommonValidationsGrantContext):
    @field_validator("grant_type")
    def grant_type_is_client_credentials(cls, grant_type: GrantType) -> GrantType:
        if (grant_type is not GrantType.CLIENT_CREDENTIALS):
            raise exceptions.InvalidGrantType()
        return grant_type

    @model_validator(mode="after")
    def client_authn_method_is_not_none(self) -> "ClientCredentialsContext":
        if (self.client.authn_method == ClientAuthnMethod.NONE):
            raise exceptions.ClientIsNotAuthenticated()
        return self

    @model_validator(mode="after")
    def requested_scopes_are_allowed(self) -> "ClientCredentialsContext":
        if (not self.client.are_scopes_allowed(requested_scopes=self.requested_scopes)):
            raise exceptions.RequestedScopesAreNotAllowedException()
        return self

    @model_validator(mode="after")
    def some_fields_must_be_none(self) -> "ClientCredentialsContext":
        """Some field in the grant context don't make sense for client credentials"""
        if (self.redirect_uri or self.authz_code or self.code_verifier):
            raise exceptions.ParameterNotAllowed()
        return self


class AuthorizationCodeContext(CommonValidationsGrantContext):
    session: "AuthnSession"

    @field_validator("grant_type")
    def grant_type_is_authz_code(cls, grant_type: GrantType) -> GrantType:
        if (grant_type is not GrantType.AUTHORIZATION_CODE):
            raise exceptions.InvalidGrantType()
        return grant_type

    @model_validator(mode="after")
    def validate_authz_code(self) -> "AuthorizationCodeContext":
        authz_code_creation: int = (
            self.session.authz_code_creation_timestamp if self.session.authz_code_creation_timestamp else 0
        )
        if (self.authz_code is None
                or (tools.get_timestamp_now() >= authz_code_creation + constants.AUTHORIZATION_CODE_TIMEOUT)):
            raise exceptions.InvalidAuthorizationCode()
        return self

    @model_validator(mode="after")
    def client_id_must_match_session(self) -> "AuthorizationCodeContext":
        if (self.client.id != self.session.client_id):
            raise exceptions.InvalidClientID()
        return self

    @model_validator(mode="after")
    def redirect_uri_must_match_session(self) -> "AuthorizationCodeContext":
        if (self.redirect_uri != self.session.redirect_uri):
            raise exceptions.InvalidRedirectURI()
        return self

    @field_validator("session")
    def user_key_must_be_in_session(cls, session: "AuthnSession") -> "AuthnSession":
        if (session.user_id is None):
            raise exceptions.UnknownUserKey()
        return session

    @model_validator(mode="after")
    def validate_pcke_requirement(self) -> "AuthorizationCodeContext":
        if (self.client.is_pcke_required and self.session.code_challenge is None):
            raise exceptions.InvalidPCKE()
        return self

    @model_validator(mode="after")
    def validate_pcke(self) -> "AuthorizationCodeContext":
        if (self.session.code_challenge):
            # Raise exception when code verifier is not provided or it doesn't match the code challenge
            if self.code_verifier is None or not tools.is_pcke_valid(
                code_verifier=self.code_verifier,
                code_challenge=self.session.code_challenge
            ):
                raise exceptions.InvalidPCKE()
        return self


@dataclass
class TokenResponse():
    access_token: str
    expires_in: int
    token_type: str = field(default=constants.BEARER_TOKEN_TYPE)
    refresh_token: str | None = None
    scope: str | None = None

#################### /authorize ####################


class AuthorizeContext(BaseModel):
    client: Client
    requested_scopes: List[str]
    response_type: constants.ResponseType
    redirect_uri: str
    code_challenge: str | None
    code_challenge_method: constants.CodeChallengeMethod

    @model_validator(mode="after")
    def validate_scopes(self: "AuthorizeContext") -> "AuthorizeContext":
        if not self.client.are_scopes_allowed(requested_scopes=self.requested_scopes):
            raise exceptions.RequestedScopesAreNotAllowedException()
        return self

    @model_validator(mode="after")
    def validate_response_type(self: "AuthorizeContext") -> "AuthorizeContext":
        if not self.client.is_response_type_allowed(response_type=self.response_type):
            raise exceptions.ResponseTypeIsNotAllowedException()
        return self

    @model_validator(mode="after")
    def validate_pcke_requirement(self: "AuthorizeContext") -> "AuthorizeContext":
        if self.client.is_pcke_required and self.code_challenge is None:
            raise exceptions.PCKEIsRequiredException()
        return self

######################################## Session ########################################


@dataclass
class AuthnSession():
    id: str
    tracking_id: str
    correlation_id: str
    callback_id: str | None
    client_id: str
    redirect_uri: str
    requested_scopes: List[str]
    state: str
    auth_policy_id: str
    next_authn_step_id: str
    user_id: str | None
    authz_code: str | None
    authz_code_creation_timestamp: int | None
    code_challenge: str | None
    params: Dict[str, Any] = field(default_factory=dict)

######################################## Auth Policy ########################################


AUTHN_POLICIES: Dict[str, "AuthnPolicy"] = {}
AUTHN_STEPS: Dict[str, "AuthnStep"] = {}


@dataclass
class AuthnStepResult():
    status: constants.AuthnStatus

    def get_response(self, session: AuthnSession) -> Response:
        raise NotImplementedError()


@dataclass
class AuthnStepInProgressResult(AuthnStepResult):
    response: Response
    status: constants.AuthnStatus = field(
        default=constants.AuthnStatus.IN_PROGRESS, init=False)

    def get_response(self, session: AuthnSession) -> Response:
        return self.response


@dataclass
class AuthnStepFailureResult(AuthnStepResult):
    error_description: str | None = None
    status: constants.AuthnStatus = field(
        default=constants.AuthnStatus.FAILURE, init=False
    )

    def get_response(self, session: AuthnSession) -> Response:
        return RedirectResponse(
            url=tools.prepare_redirect_url(url=session.redirect_uri, params={
                "error": ErrorCode.ACCESS_DENIED.value,
                "error_description": self.error_description if self.error_description else "access denied",
            }),
            status_code=status.HTTP_303_SEE_OTHER
        )


@dataclass
class AuthnStepSuccessResult(AuthnStepResult):
    status: constants.AuthnStatus = field(
        default=constants.AuthnStatus.SUCCESS, init=False
    )

    def get_response(self, session: AuthnSession) -> Response:

        if (session.authz_code is None):
            raise RuntimeError("The authorization code cannot be None")

        return RedirectResponse(
            url=tools.prepare_redirect_url(url=session.redirect_uri, params={
                "code": session.authz_code,
                "state": session.state,
            }),
            status_code=status.HTTP_303_SEE_OTHER
        )


@dataclass
class AuthnStep():
    id: str
    authn_func: Callable[
        [
            AuthnSession,
            Request
        ],
        AuthnStepResult | Awaitable[AuthnStepResult]
    ]
    success_next_step: Optional["AuthnStep"]
    failure_next_step: Optional["AuthnStep"]

    def __post_init__(self) -> None:
        # Make sure the step id is unique
        if (self.id in AUTHN_STEPS):
            raise exceptions.AuthnStepAlreadyExistsException()
        AUTHN_STEPS[self.id] = self


async def default_failure_authn_func(session: AuthnSession, request: Request) -> AuthnStepResult:
    return AuthnStepFailureResult(error_description="access denied")

# Step that always returns failure
default_failure_step = AuthnStep(
    id="default_failure_step_42",
    authn_func=default_failure_authn_func,
    success_next_step=None,
    failure_next_step=None
)


@dataclass
class AuthnPolicy():
    id: str
    is_available: Callable[[Client, Request], bool]
    first_step: AuthnStep
    get_extra_token_claims: Callable[
        [AuthnSession],
        Dict[str, str]
    ] | None = None

    def __post_init__(self) -> None:
        # Make sure the policy id is unique
        if (self.id in AUTHN_POLICIES):
            raise exceptions.AuthnPolicyAlreadyExistsException()
        AUTHN_POLICIES[self.id] = self
