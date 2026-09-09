from src.sanitizer import PIISanitizer


def test_secret_is_blocked():

    sanitizer = PIISanitizer()

    text = (
        "My API key is "
        "API_KEY=abcdefghijklmnopqrstuvwxyz123456"
    )

    result = sanitizer.sanitize(text)

    print("\nSTATUS:")
    print(result["status"])

    print("\nDETECTIONS:")

    for detection in result["detections"]:
        print(
            detection.entity_type,
            detection.action,
            detection.risk_score
        )

    assert result["status"] == "BLOCKED"