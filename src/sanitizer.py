from .detector import PIIDetector
from .secret_detector import SecretDetector
from .tokenizer import PIITokenizer
from .vault import PIIVault
from .overlap import OverlapResolver
from .masker import PIIMasker
from .risk import RiskEngine
from .policy import PolicyEngine, PolicyAction


class PIISanitizer:

    def __init__(
        self,
        detector: PIIDetector | None = None,
        secret_detector: SecretDetector | None = None,
    ):
        self.detector = detector or PIIDetector()
        self.secret_detector = secret_detector or SecretDetector()

        self.overlap_resolver = OverlapResolver()

        self.risk_engine = RiskEngine()
        self.policy_engine = PolicyEngine()
        self.masker = PIIMasker()

    def sanitize(self, text: str):

        # --------------------------------
        # 1. Detect PII
        # --------------------------------

        pii_detections = self.detector.detect(text)

        # --------------------------------
        # 2. Detect secrets
        # --------------------------------

        secret_detections = (
            self.secret_detector.detect(text)
        )

        detections = (
            pii_detections +
            secret_detections
        )

        # --------------------------------
        # 3. Resolve overlaps
        # --------------------------------

        detections = self.overlap_resolver.resolve(
            detections
        )

        # --------------------------------
        # 4. Risk + policy
        # --------------------------------

        for detection in detections:

            detection.risk_score = (
                self.risk_engine.calculate(
                    detection
                )
            )

            detection.action = (
                self.policy_engine.decide(
                    entity_type=detection.entity_type,
                    confidence=detection.score,
                    risk_score=detection.risk_score
                ).value
            )

        # --------------------------------
        # 5. Block critical information
        # --------------------------------

        blocked = [
            d for d in detections
            if d.action == PolicyAction.BLOCK.value
        ]

        if blocked:

            return {
                "status": "BLOCKED",
                "safe_text": None,
                "detections": detections,
                "vault": None,
                "reason": "Sensitive information detected"
            }

        # --------------------------------
        # 6. Apply Tokenize & Mask policies
        # --------------------------------

        tokenizable = [
            d for d in detections
            if d.action == PolicyAction.TOKENIZE.value
        ]

        maskable = [
            d for d in detections
            if d.action == PolicyAction.MASK.value
        ]

        vault = PIIVault()

        # Tokenize and store mapping for reversible PII
        counters: dict[str, int] = {}
        value_to_token: dict[tuple[str, str], str] = {}

        for detection in tokenizable:
            key = (
                detection.entity_type,
                detection.original_value
            )

            if key not in value_to_token:
                counters[detection.entity_type] = (
                    counters.get(detection.entity_type, 0) + 1
                )
                token = (
                    f"[{detection.entity_type}_"
                    f"{counters[detection.entity_type]}]"
                )
                value_to_token[key] = token
                vault.store(token, detection.original_value)

            detection.token = value_to_token[key]

        # Prepare unified replacements sorted right-to-left
        replacements = []
        for detection in tokenizable:
            replacements.append((detection.start, detection.end, detection.token))

        for detection in maskable:
            masked_val = self.masker.mask_value(detection.original_value)
            detection.token = masked_val
            replacements.append((detection.start, detection.end, masked_val))

        # Sort replacements by start offset descending (right-to-left)
        replacements.sort(key=lambda r: r[0], reverse=True)

        safe_text = text
        for start, end, rep in replacements:
            safe_text = safe_text[:start] + rep + safe_text[end:]

        return {
            "status": "SAFE",
            "safe_text": safe_text,
            "detections": detections,
            "vault": vault
        }