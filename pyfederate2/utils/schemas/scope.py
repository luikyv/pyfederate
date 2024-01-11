from dataclasses import dataclass
from pydantic import BaseModel


@dataclass
class Scope:
    name: str
    description: str

    def to_output(self) -> "ScopeAPIOut":
        raise NotImplementedError()


class BaseScopeAPI(BaseModel):
    name: str
    description: str


class ScopeAPIIn(BaseScopeAPI):
    pass

    def to_scope(self) -> Scope:
        raise NotImplementedError()


class ScopeAPIOut(BaseScopeAPI):
    pass
