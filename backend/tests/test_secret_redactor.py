from app.core.redactor import SecretRedactor


def test_redact_aws_access_key():
    raw_text = "Found leaked key: AKIAIOSFODNN7EXAMPLE in config.py"
    redacted = SecretRedactor.redact(raw_text)
    assert "AKIAIOSFODNN7EXAMPLE" not in redacted
    assert "[REDACTED_AWS_ACCESS_KEY_ID]" in redacted


def test_redact_aws_secret_key():
    raw_text = 'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"'
    redacted = SecretRedactor.redact(raw_text)
    assert "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" not in redacted
    assert "[REDACTED_AWS_SECRET_KEY]" in redacted


def test_redact_github_pat():
    raw_text = "Authorization token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    redacted = SecretRedactor.redact(raw_text)
    assert "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" not in redacted
    assert "[REDACTED_GITHUB_PAT]" in redacted


def test_redact_private_key():
    raw_text = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEA0Y1p1+fakekeycontentforTestingPurposesOnly=="
        "-----END RSA PRIVATE KEY-----"
    )
    redacted = SecretRedactor.redact(raw_text)
    assert "BEGIN RSA PRIVATE KEY" not in redacted
    assert "[REDACTED_PRIVATE_KEY]" in redacted


def test_redact_database_uri_password():
    raw_text = "DATABASE_URL=postgres://app_user:SuperSecretPassword123!@db.internal:5432/production"
    redacted = SecretRedactor.redact(raw_text)
    assert "SuperSecretPassword123!" not in redacted
    assert "postgres://app_user:[REDACTED_PASSWORD]@db.internal:5432/production" in redacted


def test_redact_generic_secret_assignment():
    raw_text = 'api_key: "SuperConfidentialKey12345"'
    redacted = SecretRedactor.redact(raw_text)
    assert "SuperConfidentialKey12345" not in redacted
    assert "[REDACTED_GENERIC_SECRET]" in redacted
