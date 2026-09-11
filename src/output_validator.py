import re
from dataclasses import dataclass, field
from typing import List, Optional

from .detector import PIIDetector
from .secret_detector import SecretDetector


@dataclass
class OutputValidationResult:

    is_safe: bool

    leaked_values: List[str]

    corrupted_tokens: List[str]

    detected_pii: List[str]

    reason: str


class OutputValidator:

    COMMON_WORDS = {
        "will", "may", "can", "art", "rob", "bill", "mark", "dean", "long",
        "in", "us", "it", "at", "as", "by", "or", "an", "on", "am", "is", "be",
        "me", "my", "he", "she", "we", "do", "so", "no", "if", "up", "out"
    }

    def __init__(
        self,
        detector: Optional[PIIDetector] = None,
        secret_detector: Optional[SecretDetector] = None,
    ):
        self.detector = detector or PIIDetector()
        self.secret_detector = secret_detector or SecretDetector()

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
            if not original_value or not original_value.strip():
                continue

            # Word-boundary case-insensitive search
            pattern = re.compile(
                rf"\b{re.escape(original_value.strip())}\b",
                re.IGNORECASE
            )

            if pattern.search(response):
                # If the token itself is preserved in the response and original_value is a common word,
                # don't falsely flag common words like "will" or "may"
                val_lower = original_value.strip().lower()
                if token in response and val_lower in self.COMMON_WORDS:
                    continue

                leaked_values.append(token)

        # =====================================================
        # 2. Check malformed versions of our tokens
        # =====================================================

        for token in vault_mapping:

            if token in response:
                continue

            token_name = token.strip("[]_")

            # Match corrupted or unbracketed variations of token_name ensuring word boundary
            pattern = re.compile(
                rf"(?<![A-Za-z0-9_])[\[\(<_\s]*"
                rf"{re.escape(token_name)}"
                rf"[\]\)>_\s]*(?![A-Za-z0-9_])",
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
                " [REDACTED] "
            )

        # =====================================================
        # 4. Scan remaining text for NEW PII & SECRETS
        # =====================================================

        pii_detections = self.detector.detect(
            scan_text
        )

        secret_detections = self.secret_detector.detect(
            scan_text
        )

        # Filter out benign conversational entities like DATE_TIME that are expected in LLM output
        EXCLUDED_FROM_OUTPUT_CHECK = {"DATE_TIME"}

        detected_issues = [
            detection.entity_type
            for detection in (pii_detections + secret_detections)
            if detection.entity_type not in EXCLUDED_FROM_OUTPUT_CHECK
        ]

        # =====================================================
        # 5. Security decision
        # =====================================================

        if leaked_values:
            return OutputValidationResult(
                is_safe=False,
                leaked_values=leaked_values,
                corrupted_tokens=corrupted_tokens,
                detected_pii=detected_issues,
                reason="Original PII leaked by LLM"
            )

        if corrupted_tokens:
            return OutputValidationResult(
                is_safe=False,
                leaked_values=[],
                corrupted_tokens=corrupted_tokens,
                detected_pii=detected_issues,
                reason="Protected placeholder was corrupted"
            )

        if detected_issues:
            return OutputValidationResult(
                is_safe=False,
                leaked_values=[],
                corrupted_tokens=[],
                detected_pii=detected_issues,
                reason="New PII or secret detected in LLM output"
            )

        return OutputValidationResult(
            is_safe=True,
            leaked_values=[],
            corrupted_tokens=[],
            detected_pii=[],
            reason="Output passed security validation"
        )