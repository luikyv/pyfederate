from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Any
import bcrypt

from .constants import ErrorCode, TokenType, SECRET_ENCODING
from .helpers import generate_client_id, generate_client_secret, hash_secret

@dataclass
class Scope():
    name: str
    description: str

@dataclass
class ClientBase():
    scopes: List[str]

@dataclass
class ClientUpsert(ClientBase):
    id: str = field(default_factory=generate_client_id)
    secret: str = field(default_factory=generate_client_secret)
    hashed_secret: Optional[str] = field(init=False)

    def __post_init__(self) -> None:
        self.hashed_secret = hash_secret(secret=self.secret)
    
    def to_dict(self) -> Dict[str, Any]:
        self_dict = asdict(self)
        self_dict.pop("secret")
        return self_dict

@dataclass
class Client(ClientBase):
    id: str
    hashed_secret: str

    def is_authenticated(self, client_secret: str) -> bool:
        return bcrypt.checkpw(
            password=client_secret.encode(SECRET_ENCODING),
            hashed_password=self.hashed_secret.encode(SECRET_ENCODING)
        )
    
    def are_scopes_allowed(self, scopes: List[str]) -> bool:
        return set(scopes).issubset(set(self.scopes))

########## API Models ##########

@dataclass
class ClientIn(ClientBase):
    pass

@dataclass
class ClientOut(ClientBase):
    id: str

@dataclass
class ScopeIn(Scope):
    pass

@dataclass
class ScopeOut(Scope):
    pass

@dataclass
class TokenResponse():
    access_token: str
    token_type: TokenType
    expires_in: int
    refresh_token: Optional[str] = None
    scope: Optional[str] = None