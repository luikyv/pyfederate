from typing import Dict, List
from dataclasses import dataclass, field


@dataclass
class AuthnInfo:
    subject: str
    client_id: str
    scopes: List[str]
    additional_info: Dict[str, str] = field(default_factory=dict)
