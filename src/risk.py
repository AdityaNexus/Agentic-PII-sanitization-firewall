from .models import PIIDetection


class RiskEngine:

    # How sensitive each entity type is.
    SENSITIVITY = {
        "PERSON": 0.30,
        "EMAIL_ADDRESS": 0.50,
        "PHONE_NUMBER": 0.60,
        "LOCATION": 0.30,

        "IP_ADDRESS": 0.40,

        "CREDIT_CARD": 0.95,
        "US_SSN": 1.00,

        "PASSWORD": 1.00,
        "API_KEY": 1.00,
        "PRIVATE_KEY": 1.00,
    }

    def calculate(self, detection: PIIDetection) -> float:

        sensitivity = self.SENSITIVITY.get(
            detection.entity_type,
            0.50
        )

        confidence = detection.score

        risk = sensitivity * confidence

        return round(risk, 3)