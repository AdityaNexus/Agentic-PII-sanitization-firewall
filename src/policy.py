from enum import Enum


class PolicyAction(str, Enum):
    ALLOW = "ALLOW"
    TOKENIZE = "TOKENIZE"
    MASK = "MASK"
    BLOCK = "BLOCK"


class PolicyEngine:

    def __init__(self):

        self.entity_policies = {

            "PERSON": PolicyAction.TOKENIZE,

            "EMAIL_ADDRESS": PolicyAction.TOKENIZE,

            "PHONE_NUMBER": PolicyAction.TOKENIZE,

            "LOCATION": PolicyAction.TOKENIZE,

            "IP_ADDRESS": PolicyAction.TOKENIZE,

            "CREDIT_CARD": PolicyAction.MASK,

            "US_SSN": PolicyAction.BLOCK,

            "PASSWORD": PolicyAction.BLOCK,

            "JWT": PolicyAction.BLOCK,

            "API_KEY": PolicyAction.BLOCK,

            "PRIVATE_KEY": PolicyAction.BLOCK,

            "DATABASE_URL": PolicyAction.BLOCK,
        }

    def decide(
        self,
        entity_type: str,
        confidence: float,
        risk_score: float
    ) -> PolicyAction:

        # Very low confidence.
        if confidence < 0.50:
            return PolicyAction.ALLOW

        # Extremely high-risk information.
        if risk_score >= 0.90:
            return PolicyAction.BLOCK

        return self.entity_policies.get(
            entity_type,
            PolicyAction.TOKENIZE
        )