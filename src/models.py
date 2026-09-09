from dataclasses import dataclass
from typing import Optional

@dataclass
class PIIDetection:
    entity_type: str
    start: int
    end: int
    score: float
    original_value: str
    token: Optional[str] = None
    action:Optional[str] = None
    risk_score:Optional[float] = None 
    