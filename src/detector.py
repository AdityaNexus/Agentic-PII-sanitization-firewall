from presidio_analyzer import AnalyzerEngine
try:
    from .models import PIIDetection
except ImportError:
    from models import PIIDetection

class PIIDetector:

    def __init__(self):
        self.analyzer = AnalyzerEngine()

    def detect(self, text: str) -> list[PIIDetection]:
        results = self.analyzer.analyze(
            text=text,
            language="en"
        )

        detections = []

        for result in results:
            detections.append(
                PIIDetection(
                    entity_type=result.entity_type,
                    start=result.start,
                    end=result.end,
                    score=result.score,
                    original_value=text[result.start:result.end]
                )
            )

        return detections