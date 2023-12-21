from dataclasses import dataclass
from pydantic import BaseModel

######################################## Scope ########################################


@dataclass
class Scope:
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
