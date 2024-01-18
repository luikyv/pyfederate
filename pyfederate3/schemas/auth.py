from typing import Dict, List
from dataclasses import dataclass, field


@dataclass
class AuthnInfo:
    subject: str
    client_id: str
    scopes: List[str]
    additional_info: Dict[str, str] = field(default_factory=dict)


@dataclass
class NextAuthnSteps:
    step_id: str
    next_step_id_if_success: str | None
    next_step_id_if_failure: str | None


@dataclass
class AuthnStepChain:
    first_step_id: str
    # Map an authn step to its next steps
    next_authn_step_map: Dict[str, NextAuthnSteps]
