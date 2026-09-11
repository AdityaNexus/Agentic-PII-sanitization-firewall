import re
from .models import PIIDetection


class SecretDetector:

    PATTERNS = {
        "API_KEY": re.compile(
            r"(?i)\b(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token)"
            r"\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{16,})|"
            r"\b(?:sk-(?:proj-|admin-|live-)?[A-Za-z0-9_\-]{20,})|"
            r"\b(?:AKIA[0-9A-Z]{16})|"
            r"\b(?:gh[pousr]_[A-Za-z0-9_]{36,})|"
            r"\b(?:xox[baprs]-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{24,})"
        ),

        "JWT": re.compile(
            r"\beyJ[A-Za-z0-9_-]+\."
            r"[A-Za-z0-9_-]+\."
            r"[A-Za-z0-9_-]+\b"
        ),

        "PRIVATE_KEY": re.compile(
            r"-----BEGIN "
            r"(?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----"
        ),

        "DATABASE_URL": re.compile(
            r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|mssql|amqp)"
            r"://[^\s]+"
        ),
    }

    def detect(self, text: str) -> list[PIIDetection]:

        detections = []

        for entity_type, pattern in self.PATTERNS.items():

            for match in pattern.finditer(text):

                detections.append(
                    PIIDetection(
                        entity_type=entity_type,
                        start=match.start(),
                        end=match.end(),
                        score=0.99,
                        original_value=match.group(0)
                    )
                )

        return detections