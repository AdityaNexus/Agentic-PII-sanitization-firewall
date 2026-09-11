from unittest.mock import MagicMock, patch
from src.agent import (
    app,
    sanitize_node,
    route_after_sanitize,
    output_firewall_node,
    route_after_output,
    retry_node,
    deanonymize_node,
    block_node,
)


def test_sanitize_node_blocks_critical_secrets():
    state = {
        "input_text": "Here is my key: API_KEY=abcdefghijklmnopqrstuvwxyz123456",
    }
    result = sanitize_node(state)
    assert result["input_status"] == "BLOCKED"
    assert result["security_status"] == "BLOCKED"
    assert "API_KEY" in result["detected_issues"]
    assert route_after_sanitize(result) == "block"


def test_sanitize_node_allows_and_tokenizes_safe_input():
    state = {
        "input_text": "Contact me at alice.smith@example.com",
    }
    result = sanitize_node(state)
    assert result["input_status"] == "SAFE"
    assert "[EMAIL_ADDRESS_1]" in result["safe_text"]
    assert result["vault_mapping"]["[EMAIL_ADDRESS_1]"] == "alice.smith@example.com"
    assert route_after_sanitize(result) == "reason"


def test_output_firewall_node_repairs_and_validates():
    state = {
        "llm_response": "Hello <EMAIL_ADDRESS_1>, your request is confirmed.",
        "vault_mapping": {"[EMAIL_ADDRESS_1]": "alice.smith@example.com"},
    }
    result = output_firewall_node(state)
    # OutputRepairer should have repaired <EMAIL_ADDRESS_1> to [EMAIL_ADDRESS_1]
    assert result["llm_response"] == "Hello [EMAIL_ADDRESS_1], your request is confirmed."
    assert result["is_valid"] is True
    assert result["security_status"] == "SAFE"
    assert route_after_output(result | {"retry_count": 0}) == "deanonymize"


def test_output_firewall_node_catches_leak_and_routes_to_retry():
    state = {
        "llm_response": "Your email is alice.smith@example.com",
        "vault_mapping": {"[EMAIL_ADDRESS_1]": "alice.smith@example.com"},
    }
    result = output_firewall_node(state)
    assert result["is_valid"] is False
    assert route_after_output(result | {"retry_count": 0}) == "retry"
    assert route_after_output(result | {"retry_count": 3}) == "block"


def test_retry_node_increments_count():
    state = {
        "retry_count": 1,
    }
    result = retry_node(state)
    assert result["retry_count"] == 2
    assert "retry_instruction" in result


def test_deanonymize_restores_tokens():
    state = {
        "llm_response": "Welcome [PERSON_1], your email is [EMAIL_ADDRESS_1].",
        "vault_mapping": {
            "[PERSON_1]": "Alice",
            "[EMAIL_ADDRESS_1]": "alice@example.com",
        },
    }
    result = deanonymize_node(state)
    assert result["final_output"] == "Welcome Alice, your email is alice@example.com."
    assert result["security_status"] == "SAFE"


def test_block_node_returns_safe_refusal():
    result = block_node({})
    assert "can't safely provide" in result["final_output"]
    assert result["security_status"] == "BLOCKED"