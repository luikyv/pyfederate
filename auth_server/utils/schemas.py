from dataclasses import dataclass, asdict
from pydantic import BaseModel
from typing import Optional
import bcrypt
import secrets
import string

from .constants import ErrorCode, TokenType, Config
from .exceptions import CannotSetSecretAndHashedSecretForClient

@dataclass
class Client():
    client_id: str
    client_secret: Optional[str] = None
    hashed_client_secret: Optional[str] = None

    def __post_init__(self) -> None:

        if(
            self.client_secret is not None
            and self.hashed_client_secret is not None
        ):
            raise CannotSetSecretAndHashedSecretForClient("The Client class is responsible for generating the secret and its hashed version")

        if(
            self.client_secret is None
            and self.hashed_client_secret is None
        ):
            alphabet = string.ascii_letters + string.digits
            self.client_secret = "".join(secrets.choice(alphabet) for i in range(Config.CLIENT_SECRET_LENGH))
            self.hashed_client_secret = bcrypt.hashpw(self.client_secret.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
        
        if(
            self.client_secret is not None
            and self.hashed_client_secret is None
        ):
            self.hashed_client_secret = bcrypt.hashpw(self.client_secret.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    def is_authenticated(self, client_secret: str) -> bool:
        return bcrypt.checkpw(
            password=client_secret.encode("utf-8"),
            hashed_password=self.hashed_client_secret.encode("utf-8") #type: ignore
        )

########## API Models ##########

@dataclass
class ErrorMessage():
    error_code: ErrorCode
    error_description: str

    def dict(self):
        return {
            "error_code": self.error_code.value,
            "error_description": self.error_description,
        }

class TokenResponse(BaseModel):
    access_token: str
    token_type: TokenType
    expires_in: int
    refresh_token: Optional[str] = None
    scope: Optional[str] = None