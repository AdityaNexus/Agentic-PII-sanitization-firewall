from src.secret_detector import SecretDetector
def test_api_key_detection():

    detector = SecretDetector()

    text = (
        "Deploy using "
        "API_KEY=abcdefghijklmnopqrstuvwxyz123456"
    )

    results = detector.detect(text)

    assert len(results) == 1

    assert results[0].entity_type == "API_KEY"

    print("\nDetected:")
    print(results[0])


def test_jwt_detection():

    detector = SecretDetector()

    text = (
        "Authorization: "
        "eyJhbGciOiJIUzI1NiJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )

    results = detector.detect(text)

    assert len(results) == 1

    assert results[0].entity_type == "JWT"