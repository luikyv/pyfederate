from dataclasses import dataclass
from pydantic import BaseModel


@dataclass
class ScopeInfo:
    name: str
    description: str


#################### API Models ####################


class BaseScope(BaseModel):
    name: str
    description: str


class ScopeIn(BaseScope):
    pass


class ScopeOut(BaseScope):
    pass
