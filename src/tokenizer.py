from .models import PIIDetection
from .vault import PIIVault


class PIITokenizer:

    def __init__(self, vault: PIIVault):
        self.vault = vault

    def tokenize(
        self,
        text: str,
        detections: list[PIIDetection]
    ) -> str:

        counters: dict[str, int] = {}
        value_to_token: dict[tuple[str, str], str] = {}

        for detection in detections:

            key = (
                detection.entity_type,
                detection.original_value
            )

            # Reuse token for the same entity/value
            if key not in value_to_token:

                counters[detection.entity_type] = (
                    counters.get(detection.entity_type, 0) + 1
                )

                token = (
                    f"[{detection.entity_type}_"
                    f"{counters[detection.entity_type]}]"
                )

                value_to_token[key] = token

                self.vault.store(
                    token,
                    detection.original_value
                )

            detection.token = value_to_token[key]

        # Replace from right → left so offsets remain valid
        sorted_detections = sorted(detections, key=lambda d: d.start, reverse=True)
        for detection in sorted_detections:
            text = (
                text[:detection.start]
                + detection.token
                + text[detection.end:]
            )

        return text