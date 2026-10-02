from functools import lru_cache
from typing import Self

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_INSECURE_DEV_SECRET = "dev-insecure-session-secret-do-not-use-in-production"
_INSECURE_DEV_API_ACCESS_TOKEN = "dev-insecure-api-access-token-do-not-use-in-production"
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
    api_access_token: str | None = None
    cors_origins: str = "http://localhost:5173"
    max_upload_bytes: int = 50 * 1024 * 1024
    max_spec_bytes: int = 5 * 1024 * 1024
    max_archive_bytes: int = 25 * 1024 * 1024
    max_files_per_scan: int = 2_000
    max_uncompressed_bytes: int = 50 * 1024 * 1024
    max_individual_file_bytes: int = 1 * 1024 * 1024
    api_client_tokens: str = ""
    max_active_scans: int = 10
    max_concurrent_scans_per_client: int = 2
    max_worker_processes: int = 2
    scan_timeout_seconds: float = 300.0
    scan_rate_limit_requests: int = 20
    scan_rate_limit_window_seconds: int = 60
    worker_max_memory_bytes: int = 512 * 1024 * 1024

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

            if not self.api_access_token:
                raise ValueError("API_ACCESS_TOKEN must be explicitly configured in production.")
            if self.api_access_token in _DISALLOWED_PRODUCTION_SECRETS:
                raise ValueError(
                    "Insecure or placeholder API_ACCESS_TOKEN is not allowed in production."
                )
            if len(self.api_access_token) < 32:
                raise ValueError(
                    "API_ACCESS_TOKEN must be at least 32 characters in production environments."
                )

        else:
            if not self.session_secret:
                self.session_secret = _INSECURE_DEV_SECRET
            if not self.api_access_token:
                self.api_access_token = _INSECURE_DEV_API_ACCESS_TOKEN

        positive_limits = {
            "MAX_UPLOAD_BYTES": self.max_upload_bytes,
            "MAX_SPEC_BYTES": self.max_spec_bytes,
            "MAX_ARCHIVE_BYTES": self.max_archive_bytes,
            "MAX_FILES_PER_SCAN": self.max_files_per_scan,
            "MAX_UNCOMPRESSED_BYTES": self.max_uncompressed_bytes,
            "MAX_INDIVIDUAL_FILE_BYTES": self.max_individual_file_bytes,
            "SCAN_RATE_LIMIT_REQUESTS": self.scan_rate_limit_requests,
            "SCAN_RATE_LIMIT_WINDOW_SECONDS": self.scan_rate_limit_window_seconds,
            "WORKER_MAX_MEMORY_BYTES": self.worker_max_memory_bytes,
            "MAX_ACTIVE_SCANS": self.max_active_scans,
            "MAX_CONCURRENT_SCANS_PER_CLIENT": self.max_concurrent_scans_per_client,
            "MAX_WORKER_PROCESSES": self.max_worker_processes,
            "SCAN_TIMEOUT_SECONDS": self.scan_timeout_seconds,
        }
        for name, value in positive_limits.items():
            if value <= 0:
                raise ValueError(f"{name} must be greater than zero.")

        if self.max_spec_bytes > self.max_upload_bytes:
            raise ValueError("MAX_SPEC_BYTES cannot exceed MAX_UPLOAD_BYTES.")
        if self.max_archive_bytes > self.max_upload_bytes:
            raise ValueError("MAX_ARCHIVE_BYTES cannot exceed MAX_UPLOAD_BYTES.")

        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
