from typing import Dict, List
from dataclasses import dataclass, field


@dataclass
class AuthnInfo:
    subject: str
    client_id: str
    scopes: List[str]
    additional_info: Dict[str, str] = field(default_factory=dict)


@dataclass
class AuthnStepInfo:
    step_id: str
    next_step_id_if_success: str | None
    next_step_id_if_failure: str | None


@dataclass
class AuthnStepChain:
    first_step_id: str
    authn_steps: List[AuthnStepInfo]
