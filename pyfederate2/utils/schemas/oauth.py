from dataclasses import dataclass


@dataclass
class ClientAuthnContext:
    secret: str | None
