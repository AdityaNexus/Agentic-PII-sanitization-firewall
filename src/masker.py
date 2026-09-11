from .models import PIIDetection


class PIIMasker:

    @staticmethod
    def mask_value(value: str) -> str:
        if len(value) <= 4:
            return "*" * len(value)
        return "*" * (len(value) - 4) + value[-4:]

    def mask(
        self,
        text: str,
        detections: list[PIIDetection]
    ) -> str:
        # Sort by start descending to preserve valid offsets
        sorted_detections = sorted(detections, key=lambda d: d.start, reverse=True)

        for detection in sorted_detections:
            masked = self.mask_value(detection.original_value)
            text = (
                text[:detection.start]
                + masked
                + text[detection.end:]
            )

        return text