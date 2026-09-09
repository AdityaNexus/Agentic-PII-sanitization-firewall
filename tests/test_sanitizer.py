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