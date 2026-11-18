"""Typed application configuration loaded from environment variables.

Design goals:
* **No hardcoded secrets.** `SECRET_KEY` and `DATABASE_URL` have no defaults.
* **Fail fast.** Invalid or weak configuration aborts start-up with a clear
  error instead of running in an insecure state.
* **Bounded values.** Limits (upload size, rate limits, token lifetime) are
  range-checked so a typo cannot disable a control (e.g. MAX_UPLOAD_MB=0).
"""

from __future__ import annotations

from functools import lru_cache
from typing import Annotated, Literal

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

# Values copied from .env.example that must never be used for real.
_PLACEHOLDER_MARKERS = ("replace-with", "change-me", "changeme")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # --- Application ---------------------------------------------------
    app_name: str = "SENTINEL SOC"
    environment: Literal["development", "test", "production"] = "development"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    log_json: bool = False
    enable_api_docs: bool = True

    # --- Database -------------------------------------------------------
    database_url: SecretStr

    # --- Security -------------------------------------------------------
    secret_key: SecretStr
    access_token_expire_minutes: int = Field(default=60, ge=5, le=1440)
    cookie_secure: bool = False
    session_cookie_name: str = "sentinel_session"
    cors_origins: Annotated[list[str], NoDecode] = Field(default_factory=list)

    # --- Rate limiting (requests per client IP per minute) --------------
    rate_limit_enabled: bool = True
    login_rate_limit_per_minute: int = Field(default=10, ge=1, le=1000)
    upload_rate_limit_per_minute: int = Field(default=10, ge=1, le=1000)
    ingest_rate_limit_per_minute: int = Field(default=60, ge=1, le=10000)
    simulation_rate_limit_per_minute: int = Field(default=10, ge=1, le=1000)

    # --- Ingestion limits -----------------------------------------------
    max_upload_mb: int = Field(default=10, ge=1, le=100)
    max_line_length: int = Field(default=8192, ge=256, le=65536)
    max_lines_per_upload: int = Field(default=100_000, ge=1, le=1_000_000)
    max_ingest_batch: int = Field(default=1000, ge=1, le=10_000)

    @field_validator("cors_origins", mode="before")
    @classmethod
    def _split_origins(cls, value: object) -> object:
        if isinstance(value, str):
            return [origin.strip() for origin in value.split(",") if origin.strip()]
        return value

    @field_validator("cors_origins")
    @classmethod
    def _validate_origins(cls, origins: list[str]) -> list[str]:
        for origin in origins:
            if origin == "*" or "*" in origin:
                raise ValueError("Wildcard CORS origins are not allowed")
            if not origin.startswith(("http://", "https://")):
                raise ValueError(f"Invalid CORS origin (must include scheme): {origin!r}")
        return origins

    @field_validator("secret_key")
    @classmethod
    def _validate_secret_key(cls, value: SecretStr) -> SecretStr:
        raw = value.get_secret_value()
        if len(raw) < 32:
            raise ValueError("SECRET_KEY must be at least 32 characters long")
        if any(marker in raw.lower() for marker in _PLACEHOLDER_MARKERS):
            raise ValueError("SECRET_KEY still contains the placeholder value from .env.example")
        return value

    @field_validator("database_url")
    @classmethod
    def _validate_database_url(cls, value: SecretStr) -> SecretStr:
        if not value.get_secret_value().startswith("postgresql+psycopg://"):
            raise ValueError("DATABASE_URL must use the 'postgresql+psycopg://' driver")
        return value

    @model_validator(mode="after")
    def _production_hardening(self) -> Settings:
        if self.environment == "production":
            if not self.cookie_secure:
                raise ValueError("COOKIE_SECURE must be true in production")
            if self.log_level == "DEBUG":
                raise ValueError("LOG_LEVEL=DEBUG is not allowed in production")
        return self

    @property
    def max_upload_bytes(self) -> int:
        return self.max_upload_mb * 1024 * 1024


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide settings (read once from the environment)."""
    return Settings()
