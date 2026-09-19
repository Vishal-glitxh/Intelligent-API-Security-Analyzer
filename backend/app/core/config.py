from functools import lru_cache
from typing import Self

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_INSECURE_DEV_SECRET = "dev-insecure-session-secret-do-not-use-in-production"
_DISALLOWED_PRODUCTION_SECRETS = {
    _INSECURE_DEV_SECRET,
    "development-only-replace-me",
    "secret",
    "changeme",
    "password",
}


class Settings(BaseSettings):
    app_name: str = "Intelligent API Security Analyzer"
    environment: str = "development"
    database_url: str = "postgresql+psycopg://analyzer:analyzer@localhost:5432/api_security"
    session_secret: str | None = None
    cors_origins: str = "http://localhost:5173"
    max_upload_bytes: int = 50 * 1024 * 1024
    max_files_per_scan: int = 10_000
    max_uncompressed_bytes: int = 500 * 1024 * 1024

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    @model_validator(mode="after")
    def validate_session_secret(self) -> Self:
        is_prod = self.environment.strip().lower() == "production"

        if is_prod:
            if not self.session_secret:
                raise ValueError("SESSION_SECRET must be explicitly configured in production.")
            if self.session_secret in _DISALLOWED_PRODUCTION_SECRETS:
                raise ValueError(
                    "Insecure or placeholder SESSION_SECRET is not allowed in production."
                )

            if len(self.session_secret) < 32:
                raise ValueError(
                    "SESSION_SECRET must be at least 32 characters in production environments."
                )

        else:
            if not self.session_secret:
                self.session_secret = _INSECURE_DEV_SECRET

        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
