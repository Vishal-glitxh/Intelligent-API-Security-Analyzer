import pytest
from app.core.config import Settings


def test_development_fallback_secret() -> None:
    settings = Settings(
        environment="development",
        session_secret=None,
    )
    assert settings.session_secret is not None
    assert "dev-insecure-session-secret" in settings.session_secret


def test_explicit_configuration_injection() -> None:
    custom_secret = "a" * 32
    settings = Settings(
        environment="testing",
        session_secret=custom_secret,
        app_name="Custom Test Analyzer",
    )
    assert settings.session_secret == custom_secret
    assert settings.app_name == "Custom Test Analyzer"


def test_production_requires_session_secret() -> None:
    with pytest.raises(
        ValueError, match="SESSION_SECRET must be explicitly configured in production"
    ):
        Settings(
            environment="production",
            session_secret="",
        )


def test_production_rejects_short_secret() -> None:
    with pytest.raises(ValueError, match="SESSION_SECRET must be at least 32 characters"):
        Settings(
            environment="production",
            session_secret="too-short-secret",
        )


def test_production_rejects_insecure_placeholders() -> None:
    with pytest.raises(ValueError, match="Insecure or placeholder SESSION_SECRET is not allowed"):
        Settings(
            environment="production",
            session_secret="development-only-replace-me",
        )


def test_production_accepts_secure_secret() -> None:
    valid_secret = "super-secure-production-secret-key-that-is-long-enough"
    settings = Settings(
        environment="production",
        session_secret=valid_secret,
    )
    assert settings.session_secret == valid_secret
