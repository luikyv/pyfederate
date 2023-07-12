from dataclasses import dataclass, field, asdict
import typing
import bcrypt
import jwt
import time

from . import constants
from .constants import TokenClaim
from .import tools

######################################## Token ########################################

@dataclass
class TokenInfo():
    subject: str
    issuer: str
    issued_at: int
    expiration: int
    client_id: str
    scopes: typing.List[str]
    id: str = field(default_factory=tools.generate_uuid)
    additional_info: typing.Optional[typing.Dict[str, str]] = None

    def to_jwt_payload(self) -> typing.Dict[str, typing.Any]:
        payload = {
            TokenClaim.JWT_ID.value: self.id,
            TokenClaim.SUBJECT.value: self.subject,
            TokenClaim.ISSUER.value: self.issuer,
            TokenClaim.ISSUED_AT.value: self.issued_at,
            TokenClaim.EXPIRATION.value: self.expiration,
            TokenClaim.CLIENT_ID.value: self.client_id,
            TokenClaim.SCOPE.value: " ".join(self.scopes)
        }
        if self.additional_info: payload = self.additional_info | payload

        return payload

@dataclass
class BearerToken:
    id: str
    info: TokenInfo
    token: str

@dataclass
class TokenModel():
    id: str
    issuer: str
    expires_in: int

    def generate_token(
        self,
        client_id: str,
        subject: str,
        scopes: typing.List[str]
    ) -> BearerToken:
        raise NotImplementedError()
    
    def to_output(self) -> "TokenModelOut":
        raise NotImplementedError()

@dataclass
class TokenModelUpsert(TokenModel):
    token_type: constants.TokenType
    key_id: typing.Optional[str]
    signing_algorithm: typing.Optional[constants.SigningAlgorithm]

    def to_db_dict(self) -> typing.Dict[str, typing.Any]:
        self_dict = asdict(self)
        
        self_dict["token_type"] = self.token_type.value
        if self.signing_algorithm is not None: self_dict["signing_algorithm"] = self.signing_algorithm.value
        return self_dict

@dataclass
class JWTTokenModel(TokenModel):
    key_id: str
    key: str
    signing_algorithm: constants.SigningAlgorithm

    def generate_token(
        self,
        client_id: str,
        subject: str,
        scopes: typing.List[str]
    ) -> BearerToken:

        timestamp_now = int(time.time())
        token_info = TokenInfo(
            subject=subject,
            issuer=self.issuer,
            issued_at=timestamp_now,
            expiration=timestamp_now + self.expires_in,
            client_id=client_id,
            scopes=scopes
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

@dataclass
class TokenModelIn(TokenModel):
    token_type: constants.TokenType
    key_id: typing.Optional[str]
    signing_algorithm: typing.Optional[constants.SigningAlgorithm]

    def to_upsert(self) -> TokenModelUpsert:
        return TokenModelUpsert(
            id=self.id,
            issuer=self.issuer,
            expires_in=self.expires_in,
            token_type=self.token_type,
            key_id=self.key_id,
            signing_algorithm=self.signing_algorithm
        )

@dataclass
class TokenModelOut(TokenModel):
    token_type: constants.TokenType
    key_id: typing.Optional[str]
    signing_algorithm: typing.Optional[constants.SigningAlgorithm]

######################################## Scope ########################################

@dataclass
class Scope():
    name: str
    description: str

    def to_output(self) -> "ScopeOut":
        return ScopeOut(
            name=self.name,
            description=self.description
        )

@dataclass
class ScopeUpsert(Scope):
    def to_db_dict(self) -> typing.Dict[str, typing.Any]:
        self_dict = asdict(self)
        return self_dict

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

@dataclass
class ClientBase():
    scopes: typing.List[str]

@dataclass
class ClientUpsert(ClientBase):
    token_model_id: str
    id: str = field(default_factory=tools.generate_client_id)
    secret: str = field(default_factory=tools.generate_client_secret)
    hashed_secret: typing.Optional[str] = field(init=False)

    def __post_init__(self) -> None:
        self.hashed_secret = tools.hash_secret(secret=self.secret)
    
    def to_db_dict(self) -> typing.Dict[str, typing.Any]:
        self_dict = asdict(self)
        self_dict.pop("secret")
        return self_dict

@dataclass
class Client(ClientBase):
    id: str
    hashed_secret: str
    token_model: TokenModel

    def to_output(self) -> "ClientOut":
        return ClientOut(
            id=self.id,
            scopes=self.scopes,
            token_model_id=self.token_model.id
        )

    def is_authenticated(self, client_secret: str) -> bool:
        return bcrypt.checkpw(
            password=client_secret.encode(constants.SECRET_ENCODING),
            hashed_password=self.hashed_secret.encode(constants.SECRET_ENCODING)
        )
    
    def are_scopes_allowed(self, requested_scopes: typing.List[str]) -> bool:
        return set(requested_scopes).issubset(set(self.scopes))

@dataclass
class GrantContext:
    client: Client
    token_model: TokenModel
    requested_scopes: typing.List[str]

#################### API Models ####################

@dataclass
class ClientIn(ClientBase):
    token_model_id: str

    def to_upsert(self) -> ClientUpsert:
        return ClientUpsert(
            scopes=self.scopes,
            token_model_id=self.token_model_id
        )

@dataclass
class ClientOut(ClientBase):
    id: str
    token_model_id: str

@dataclass
class TokenResponse():
    access_token: str
    expires_in: int
    token_type: str = field(default=constants.BEARER_TOKEN_TYPE)
    refresh_token: typing.Optional[str] = None
    scope: typing.Optional[str] = None

######################################## Session ########################################

@dataclass
class SessionInfo():
    tracking_id: str
    flow_id: str
    callback_id: str | None = None
    params: typing.Dict[str, typing.Any] = field(default_factory=dict)