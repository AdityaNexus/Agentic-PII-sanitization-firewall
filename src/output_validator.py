import re
from dataclasses import dataclass
from typing import List

from .detector import PIIDetector


@dataclass
class OutputValidationResult:

    is_safe: bool

    leaked_values: List[str]

    corrupted_tokens: List[str]

    detected_pii: List[str]

    reason: str


class OutputValidator:

    def __init__(self):

        self.detector = PIIDetector()


    def validate(
        self,
        response: str,
        vault_mapping: dict[str, str]
    ) -> OutputValidationResult:

        leaked_values = []

        corrupted_tokens = []

        # =====================================================
        # 1. Detect ORIGINAL PII leakage
        # =====================================================

        for token, original_value in vault_mapping.items():

            if original_value in response:

                leaked_values.append(token)


        # =====================================================
        # 2. Check malformed versions of our tokens
        # =====================================================

        for token in vault_mapping:

            if token in response:
                continue

            token_name = token.strip("[]_")

            pattern = re.compile(
                rf"[\[\]<>_]*"
                rf"{re.escape(token_name)}"
                rf"[\[\]<>_]*",
                re.IGNORECASE
            )

            if pattern.search(response):

                corrupted_tokens.append(token)


        # =====================================================
        # 3. Remove VALID firewall tokens before PII scanning
        # =====================================================

        scan_text = response

        for token in vault_mapping:

            scan_text = scan_text.replace(
                token,
                ""
            )


        # =====================================================
        # 4. Scan remaining text for NEW PII
        # =====================================================

        detections = self.detector.detect(
            scan_text
        )

        detected_pii = [
            detection.entity_type
            for detection in detections
        ]


        # =====================================================
        # 5. Security decision
        # =====================================================

        if leaked_values:

            return OutputValidationResult(
                is_safe=False,
                leaked_values=leaked_values,
                corrupted_tokens=corrupted_tokens,
                detected_pii=detected_pii,
                reason="Original PII leaked by LLM"
            )


        if corrupted_tokens:

            return OutputValidationResult(
                is_safe=False,
                leaked_values=[],
                corrupted_tokens=corrupted_tokens,
                detected_pii=detected_pii,
                reason="Protected placeholder was corrupted"
            )


        if detected_pii:

            return OutputValidationResult(
                is_safe=False,
                leaked_values=[],
                corrupted_tokens=[],
                detected_pii=detected_pii,
                reason="New PII detected in LLM output"
            )


        return OutputValidationResult(
            is_safe=True,
            leaked_values=[],
            corrupted_tokens=[],
            detected_pii=[],
            reason="Output passed security validation"
        )