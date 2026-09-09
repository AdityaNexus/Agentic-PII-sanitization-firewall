from dataclasses import dataclass, field
from typing import Dict
from uuid import uuid4

from .vault import PIIVault


@dataclass
class SecurityContext:
    request_id: str = field(
        default_factory=lambda: uuid4().hex
    )

    vault: PIIVault = field(
        default_factory=PIIVault
    )

    metadata: Dict = field(
        default_factory=dict
    )