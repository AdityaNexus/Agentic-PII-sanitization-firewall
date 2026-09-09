from .models import PIIDetection


class PIIMasker:

    def mask(
        self,
        text: str,
        detections: list[PIIDetection]
    ) -> str:

        for detection in reversed(detections):

            value = detection.original_value

            if len(value) <= 4:
                masked = "*" * len(value)
            else:
                masked = (
                    "*" * (len(value) - 4)
                    + value[-4:]
                )

            text = (
                text[:detection.start]
                + masked
                + text[detection.end:]
            )

        return text