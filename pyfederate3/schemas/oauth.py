from typing import List
from pydantic import BaseModel, Field
from dataclasses import dataclass

from ..utils.constants import GrantType, BEARER_TOKEN_TYPE


@dataclass
class GrantContext:
    grant_type: GrantType
    scopes: List[str]
    redirect_uri: str | None
    refresh_token: str | None
    authz_code: str | None
    code_verifier: str | None
    correlation_id: str | None


#################### API Models ####################


class TokenResponse(BaseModel):
    access_token: str
    expires_in: int
    token_type: str = Field(default=BEARER_TOKEN_TYPE)
    refresh_token: str | None = None
    scope: str | None = None
