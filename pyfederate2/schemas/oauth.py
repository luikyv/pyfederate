from dataclasses import dataclass

from ..constants import SigningAlgorithm


@dataclass
class ClientAuthnContext:
    secret: str | None


@dataclass
class JWKInfo:
    key_id: str
    key: str
    signing_algorithm: SigningAlgorithm
