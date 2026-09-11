from src.masker import PIIMasker
from src.models import PIIDetection
from src.overlap import OverlapResolver
from src.policy import PolicyAction, PolicyEngine
from src.risk import RiskEngine
from src.sanitizer import PIISanitizer
from src.tokenizer import PIITokenizer
from src.vault import PIIVault
from src.agent import deanonymize_node, sanitize_node


def detection(entity_type: str, start: int, end: int, score: float = 0.9):
    return PIIDetection(
        entity_type=entity_type,
        start=start,
        end=end,
        score=score,
        original_value="text",
    )


def test_vault_stores_and_restores_values():
    vault = PIIVault()
    vault.store("[EMAIL_1]", "john@gmail.com")

    assert vault.restore("Contact [EMAIL_1]") == "Contact john@gmail.com"
    assert vault.get_mapping() == {"[EMAIL_1]": "john@gmail.com"}


def test_masker_preserves_last_four_characters():
    text = "Card 1234567890123456"
    detections = [detection("CREDIT_CARD", 5, 21)]
    detections[0].original_value = text[5:21]

    assert PIIMasker().mask(text, detections) == "Card ************3456"


def test_tokenizer_reuses_token_for_duplicate_values():
    text = "John Smith called John Smith"
    detections = [
        PIIDetection("PERSON", 0, 10, 0.9, "John Smith"),
        PIIDetection("PERSON", 18, 28, 0.9, "John Smith"),
    ]
    vault = PIIVault()

    result = PIITokenizer(vault).tokenize(text, detections)

    assert result == "[PERSON_1] called [PERSON_1]"
    assert vault.get_mapping() == {"[PERSON_1]": "John Smith"}


def test_overlap_resolver_keeps_highest_confidence_match():
    detections = [
        detection("PERSON", 0, 10, 0.8),
        detection("LOCATION", 0, 10, 0.95),
        detection("EMAIL_ADDRESS", 20, 30, 0.7),
    ]

    resolved = OverlapResolver().resolve(detections)

    assert [(item.entity_type, item.start) for item in resolved] == [
        ("LOCATION", 0),
        ("EMAIL_ADDRESS", 20),
    ]


def test_risk_engine_uses_entity_sensitivity():
    assert RiskEngine().calculate(detection("CREDIT_CARD", 0, 4, 1.0)) == 0.95
    assert RiskEngine().calculate(detection("PERSON", 0, 4, 1.0)) == 0.3


def test_policy_engine_applies_confidence_and_risk_rules():
    policy = PolicyEngine()

    assert policy.decide("EMAIL_ADDRESS", 0.4, 0.2) is PolicyAction.ALLOW
    assert policy.decide("EMAIL_ADDRESS", 0.9, 0.2) is PolicyAction.TOKENIZE
    assert policy.decide("CREDIT_CARD", 0.9, 0.95) is PolicyAction.BLOCK
    assert policy.decide("CREDIT_CARD", 0.9, 0.5) is PolicyAction.MASK



def test_pii_sanitization():

    sanitizer = PIISanitizer()

    text = (
        "Hi, my name is John Smith. "
        "My email is john@gmail.com. "
        "John Smith will call you tomorrow."
    )

    result = sanitizer.sanitize(text)

    assert result["safe_text"] == (
        "Hi, my name is [PERSON_1]. "
        "My email is [EMAIL_ADDRESS_1]. "
        "[PERSON_1] will call you [DATE_TIME_1]."
    )
    assert result["vault"].get_mapping() == {
        "[PERSON_1]": "John Smith",
        "[EMAIL_ADDRESS_1]": "john@gmail.com",
        "[DATE_TIME_1]": "tomorrow",
    }


def test_agent_nodes_use_sanitizer_and_vault_contract():
    state = sanitize_node({"input_text": "john@gmail.com"})

    assert state["safe_text"] == "[EMAIL_ADDRESS_1]"
    result = deanonymize_node({
        "llm_response": "Please contact [EMAIL_ADDRESS_1]",
        "vault_mapping": state["vault_mapping"],
    })

    assert result["final_output"] == "Please contact john@gmail.com"


def test_vault_subtoken_collision_prevention():
    vault = PIIVault()
    vault.store("[PERSON_1]", "Alice")
    vault.store("[PERSON_10]", "Bob")

    text = "Team: [PERSON_10] and [PERSON_1]"
    restored = vault.restore(text)
    # [PERSON_10] must be restored to Bob, not Alice0!
    assert restored == "Team: Bob and Alice"


def test_output_validator_case_insensitive_leak_detection():
    from src.output_validator import OutputValidator
    validator = OutputValidator()
    mapping = {"[EMAIL_ADDRESS_1]": "Alice.Smith@Example.COM"}

    # Lowercase leak in LLM output
    result = validator.validate(
        response="Sending reply to alice.smith@example.com now.",
        vault_mapping=mapping,
    )
    assert result.is_safe is False
    assert "[EMAIL_ADDRESS_1]" in result.leaked_values


def test_output_validator_common_word_false_positive_resistance():
    from src.output_validator import OutputValidator
    validator = OutputValidator()
    mapping = {"[PERSON_1]": "Will"}

    # Preserving token while using English auxiliary verb 'will'
    result = validator.validate(
        response="Hello [PERSON_1], I will help you with your account today.",
        vault_mapping=mapping,
    )
    assert result.is_safe is True


def test_sanitizer_masks_credit_card_and_tokenizes_email():
    from unittest.mock import MagicMock
    mock_detector = MagicMock()
    mock_detector.detect.return_value = [
        PIIDetection("CREDIT_CARD", 5, 21, 0.8, "1234567890123456"),
        PIIDetection("EMAIL_ADDRESS", 31, 47, 0.9, "user@example.com"),
    ]
    sanitizer = PIISanitizer(detector=mock_detector)
    text = "Card 1234567890123456 email is user@example.com"
    result = sanitizer.sanitize(text)
    assert result["status"] == "SAFE"
    assert "************3456" in result["safe_text"]
    assert "[EMAIL_ADDRESS_1]" in result["safe_text"]
    assert result["vault"].get_mapping() == {"[EMAIL_ADDRESS_1]": "user@example.com"}

