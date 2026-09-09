from .detector import PIIDetector
from .secret_detector import SecretDetector
from .tokenizer import PIITokenizer
from .vault import PIIVault
from .overlap import OverlapResolver
from .masker import PIIMasker
from .risk import RiskEngine
from .policy import PolicyEngine, PolicyAction


class PIISanitizer:

    def __init__(self):

        self.detector = PIIDetector()
        self.secret_detector = SecretDetector()

        self.overlap_resolver = OverlapResolver()

        self.risk_engine = RiskEngine()
        self.policy_engine = PolicyEngine()

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
        # 6. Tokenize allowed PII
        # --------------------------------

        tokenizable = [
            d for d in detections
            if d.action == PolicyAction.TOKENIZE.value
        ]

        vault = PIIVault()

        tokenizer = PIITokenizer(vault)

        safe_text = tokenizer.tokenize(
            text,
            tokenizable
        )

        return {
            "status": "SAFE",
            "safe_text": safe_text,
            "detections": detections,
            "vault": vault
        }