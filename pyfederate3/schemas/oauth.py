from dataclasses import dataclass

from ..utils.constants import SigningAlgorithm


@dataclass
class JWKInfo:
    key_id: str
    key: str
    signing_algorithm: SigningAlgorithm
