from typing import Dict
from dataclasses import dataclass


@dataclass
class NextAuthnSteps:
    next_step_id_if_success: str | None
    next_step_id_if_failure: str | None


@dataclass
class AuthnStepChain:
    first_step_id: str
    # Map an authn step to its next steps
    next_authn_step_map: Dict[str, NextAuthnSteps]
