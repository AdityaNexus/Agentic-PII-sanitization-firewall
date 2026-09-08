# src/sanitizer.py
from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig
from typing import Dict, Tuple

class DynamicPIIVault:
    def __init__(self):
        self.analyzer = AnalyzerEngine()
        self.anonymizer = AnonymizerEngine()

    def sanitize(self, text: str) -> Tuple[str, Dict[str, str]]:
        """
        Scans text for PII, dynamically assigns tokens, and returns
        the anonymized text along with the vault mapping dictionary.
        """
        analyzer_results = self.analyzer.analyze(text=text, language='en')
        
        # Sort results by start position to ensure consistent indexing
        analyzer_results.sort(key=lambda x: x.start)

        vault_mapping: Dict[str, str] = {}
        entity_counters: Dict[str, int] = {}
        operators: Dict[str, OperatorConfig] = {}

        # Create unique tokens for each detected entity (e.g., __PERSON_1__)
        for result in analyzer_results:
            entity_type = result.entity_type
            entity_counters[entity_type] = entity_counters.get(entity_type, 0) + 1
            
            token = f"__{entity_type}_{entity_counters[entity_type]}__"
            
            # Extract exact original text slice from string
            original_value = text[result.start:result.end]
            vault_mapping[token] = original_value
            
            # Instruct Anonymizer to replace this specific entity type with our custom token
            operators[entity_type] = OperatorConfig("replace", {"new_value": token})

        anonymized_result = self.anonymizer.anonymize(
            text=text,
            analyzer_results=analyzer_results,
            operators=operators
        )

        return anonymized_result.text, vault_mapping

    @staticmethod
    def deanonymize(text: str, vault_mapping: Dict[str, str]) -> str:
        """
        Replaces custom tokens back with original PII values.
        """
        restored_text = text
        for token, original_value in vault_mapping.items():
            restored_text = restored_text.replace(token, original_value)
        return restored_text