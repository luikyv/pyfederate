from dataclasses import dataclass
from pydantic import BaseModel


@dataclass
class Scope:
    name: str
    description: str


class BaseScopeAPI(BaseModel):
    name: str
    description: str


class ScopeAPIIn(BaseScopeAPI):
    pass


class ScopeAPIOut(BaseScopeAPI):
    pass
