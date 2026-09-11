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


def test_openai_key_detection():
    detector = SecretDetector()
    text = "Use key sk-proj-1234567890abcdefghijklmnopqrstuvwxyz"
    results = detector.detect(text)
    assert len(results) >= 1
    assert results[0].entity_type == "API_KEY"


def test_aws_key_detection():
    detector = SecretDetector()
    text = "My AWS key is AKIAIOSFODNN7EXAMPLE"
    results = detector.detect(text)
    assert len(results) >= 1
    assert results[0].entity_type == "API_KEY"


def test_github_token_detection():
    detector = SecretDetector()
    text = "Clone with ghp_1234567890abcdefghijklmnopqrstuvwxyz12"
    results = detector.detect(text)
    assert len(results) >= 1
    assert results[0].entity_type == "API_KEY"


def test_database_url_detection():
    detector = SecretDetector()
    text = "Connect to postgresql://admin:secret@db.internal:5432/production"
    results = detector.detect(text)
    assert len(results) >= 1
    assert results[0].entity_type == "DATABASE_URL"