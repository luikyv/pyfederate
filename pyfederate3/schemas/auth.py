from typing import Dict, List
from dataclasses import dataclass, field

from ..utils.tools import generate_session_id, generate_callback_id
from ..utils.telemetry import tracking_id, correlation_id
from ..utils.constants import ResponseType


@dataclass
class NextAuthnSteps:
    next_step_id_if_success: str | None
    next_step_id_if_failure: str | None


@dataclass
class AuthnStepChain:
    first_step_id: str
    # Map an authn step to its next steps
    next_authn_step_map: Dict[str, NextAuthnSteps]  # Step id


@dataclass
class AuthnSession:
    policy_id: str
    current_step_id: str
    client_id: str
    redirect_uri: str
    response_types: List[ResponseType]
    scopes: List[str]
    state: str
    id: str = field(default_factory=generate_session_id)
    callback_id: str = field(default_factory=generate_callback_id)
    correlation_id: str = field(default_factory=correlation_id.get)
    tracking_id: str = field(default_factory=tracking_id.get)
