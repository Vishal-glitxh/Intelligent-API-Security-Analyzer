from pathlib import Path
from typing import Any

import pytest
from app.core.config import Settings

PRODUCTION_DATABASE_URL = "postgresql+psycopg://prod-user:prod-pass@db.internal:5432/analyzer"


def settings_without_env(*, environment: str, **overrides: object) -> Settings:
    values: dict[str, Any] = {
        "environment": environment,
        "local_dev_auth_bypass": False,
    }
    values.update(overrides)
    return Settings(**values, _env_file=None)  # type: ignore[call-arg]


def test_development_fallback_secret() -> None:
    settings = settings_without_env(
        environment="development",
        session_secret=None,
    )
    assert settings.session_secret is not None
    assert "dev-insecure-session-secret" in settings.session_secret


@pytest.mark.parametrize("environment", ["prod", "productionish", "staging", "", "unknown"])
def test_unknown_environment_labels_fail_closed(environment: str) -> None:
    with pytest.raises(ValueError, match="ENVIRONMENT must be one of"):
        settings_without_env(environment=environment)


def test_supported_environment_labels_are_normalized() -> None:
    development = settings_without_env(environment=" Development ")
    testing = settings_without_env(environment="TESTING")
    production = settings_without_env(
        environment=" Production ",
        database_url=PRODUCTION_DATABASE_URL,
        session_secret="secure-production-session-secret-over-32-characters",
        api_access_token="secure-production-api-access-token-over-32-characters",
        artifact_storage_backend="s3",
        artifact_storage_bucket="iasa-production-artifacts",
    )

    assert development.environment == "development"
    assert testing.environment == "testing"
    assert production.environment == "production"
    assert testing.api_access_token == "dev-insecure-api-access-token-do-not-use-in-production"


def test_explicit_configuration_injection() -> None:
    custom_secret = "a" * 32
    api_token = "b" * 32
    settings = settings_without_env(
        environment="testing",
        session_secret=custom_secret,
        api_access_token=api_token,
        app_name="Custom Test Analyzer",
    )
    assert settings.session_secret == custom_secret
    assert settings.app_name == "Custom Test Analyzer"


def test_settings_helper_ignores_a_developer_dotenv_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / ".env").write_text(
        "APP_NAME=from-developer-dotenv\nLOCAL_DEV_AUTH_BYPASS=true\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("APP_NAME", raising=False)

    settings = settings_without_env(environment="testing")

    assert settings.app_name == "Intelligent API Security Analyzer"
    assert settings.local_dev_auth_bypass is False


def test_production_requires_session_secret() -> None:
    with pytest.raises(
        ValueError, match="SESSION_SECRET must be explicitly configured in production"
    ):
        settings_without_env(
            environment="production",
            database_url=PRODUCTION_DATABASE_URL,
            session_secret="",
        )


def test_production_rejects_short_secret() -> None:
    with pytest.raises(ValueError, match="SESSION_SECRET must be at least 32 characters"):
        settings_without_env(
            environment="production",
            database_url=PRODUCTION_DATABASE_URL,
            session_secret="too-short-secret",
        )


def test_production_rejects_insecure_placeholders() -> None:
    with pytest.raises(ValueError, match="Insecure or placeholder SESSION_SECRET is not allowed"):
        settings_without_env(
            environment="production",
            database_url=PRODUCTION_DATABASE_URL,
            session_secret="development-only-replace-me",
        )


def test_production_rejects_the_builtin_development_fallback_secret() -> None:
    fallback_secret = "dev-insecure-session-secret-do-not-use-in-production"
    with pytest.raises(ValueError) as error:
        settings_without_env(
            environment="production",
            database_url=PRODUCTION_DATABASE_URL,
            session_secret=fallback_secret,
            api_access_token="secure-production-api-access-token-over-32-characters",
        )
    assert "Insecure or placeholder SESSION_SECRET is not allowed" in str(error.value)
    assert fallback_secret not in str(error.value)


def test_production_accepts_secure_secret() -> None:
    valid_secret = "super-secure-production-secret-key-that-is-long-enough"
    valid_api_token = "separate-production-api-token-that-is-long-enough"
    settings = settings_without_env(
        environment="production",
        database_url=PRODUCTION_DATABASE_URL,
        session_secret=valid_secret,
        api_access_token=valid_api_token,
        artifact_storage_backend="s3",
        artifact_storage_bucket="iasa-production-artifacts",
    )
    assert settings.session_secret == valid_secret


def test_production_requires_api_access_token() -> None:
    with pytest.raises(ValueError, match="API_ACCESS_TOKEN must be explicitly configured"):
        settings_without_env(
            environment="production",
            database_url=PRODUCTION_DATABASE_URL,
            session_secret="super-secure-production-secret-key-that-is-long-enough",
            api_access_token="",
        )


def test_production_rejects_local_authentication_bypass() -> None:
    with pytest.raises(ValueError, match="LOCAL_DEV_AUTH_BYPASS cannot be enabled"):
        settings_without_env(
            environment="production",
            database_url=PRODUCTION_DATABASE_URL,
            session_secret="secure-production-session-secret-over-32-characters",
            api_access_token="secure-production-api-access-token-over-32-characters",
            local_dev_auth_bypass=True,
        )


def test_production_rejects_the_development_api_token_without_echoing_it() -> None:
    development_token = "dev-insecure-api-access-token-do-not-use-in-production"
    with pytest.raises(ValueError) as error:
        settings_without_env(
            environment="production",
            database_url=PRODUCTION_DATABASE_URL,
            session_secret="secure-production-session-secret-over-32-characters",
            api_access_token=development_token,
        )
    assert "Insecure or placeholder API_ACCESS_TOKEN is not allowed" in str(error.value)
    assert development_token not in str(error.value)


def test_production_rejects_the_development_database_url_without_echoing_it() -> None:
    development_url = "postgresql+psycopg://analyzer:analyzer@localhost:5432/api_security"
    with pytest.raises(ValueError) as error:
        settings_without_env(
            environment="production",
            database_url=development_url,
            session_secret="secure-production-session-secret-over-32-characters",
            api_access_token="secure-production-api-access-token-over-32-characters",
        )
    assert "DATABASE_URL must be explicitly configured" in str(error.value)
    assert development_url not in str(error.value)


def test_production_requires_an_explicit_database_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DATABASE_URL", raising=False)
    with pytest.raises(ValueError, match="DATABASE_URL must be explicitly configured"):
        settings_without_env(
            environment="production",
            session_secret="secure-production-session-secret-over-32-characters",
            api_access_token="secure-production-api-access-token-over-32-characters",
        )


def test_production_accepts_explicit_database_url_and_strong_credentials() -> None:
    config = settings_without_env(
        environment="production",
        database_url=PRODUCTION_DATABASE_URL,
        session_secret="secure-production-session-secret-over-32-characters",
        api_access_token="secure-production-api-access-token-over-32-characters",
        local_dev_auth_bypass=False,
        artifact_storage_backend="s3",
        artifact_storage_bucket="iasa-production-artifacts",
    )
    assert config.database_url == PRODUCTION_DATABASE_URL


def test_production_accepts_private_ollama_service_name() -> None:
    config = settings_without_env(
        environment="production",
        database_url=PRODUCTION_DATABASE_URL,
        session_secret="secure-production-session-secret-over-32-characters",
        api_access_token="secure-production-api-access-token-over-32-characters",
        ollama_base_url="http://ollama:11434",
        artifact_storage_backend="s3",
        artifact_storage_bucket="iasa-production-artifacts",
    )
    assert config.ollama_base_url == "http://ollama:11434"


def test_production_rejects_unapproved_remote_ollama_host() -> None:
    with pytest.raises(ValueError, match="approved private Ollama service name"):
        settings_without_env(
            environment="production",
            database_url=PRODUCTION_DATABASE_URL,
            session_secret="secure-production-session-secret-over-32-characters",
            api_access_token="secure-production-api-access-token-over-32-characters",
            artifact_storage_backend="s3",
            artifact_storage_bucket="iasa-production-artifacts",
            ollama_base_url="http://unapproved.example:11434",
        )
