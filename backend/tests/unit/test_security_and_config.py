"""Unit tests for configuration validation, password hashing, JWTs, rate limiting and redaction."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import SecretStr, ValidationError

from app.core.config import Settings
from app.core.logging import REDACTED, redact_sensitive
from app.core.rate_limit import FixedWindowRateLimiter
from app.core.security import (
    TokenError,
    create_access_token,
    decode_access_token,
    hash_password,
    validate_password_policy,
    verify_password,
)

VALID_DB = SecretStr("postgresql+psycopg://u:p@localhost:5432/db")
VALID_SECRET = SecretStr("a-secure-random-secret-key-with-more-than-32-chars")


def test_settings_rejects_short_or_placeholder_secret() -> None:
    with pytest.raises(ValidationError, match="at least 32"):
        Settings(database_url=VALID_DB, secret_key=SecretStr("too-short"))

    with pytest.raises(ValidationError, match="placeholder"):
        Settings(
            database_url=VALID_DB,
            secret_key=SecretStr("replace-with-a-long-random-value-1234567890"),
        )


def test_settings_rejects_wildcard_cors_and_insecure_production() -> None:
    with pytest.raises(ValidationError, match="Wildcard CORS"):
        Settings(database_url=VALID_DB, secret_key=VALID_SECRET, cors_origins=["*"])

    with pytest.raises(ValidationError, match="COOKIE_SECURE"):
        Settings(
            environment="production",
            database_url=VALID_DB,
            secret_key=VALID_SECRET,
            cookie_secure=False,
        )


def test_password_hashing_and_policy() -> None:
    hashed = hash_password("StrongPassphrase!2026")
    assert hashed.startswith("$argon2id$")
    assert verify_password("StrongPassphrase!2026", hashed) is True
    assert verify_password("WrongPassphrase!2026", hashed) is False
    # Constant-work path when user does not exist (password_hash=None)
    assert verify_password("StrongPassphrase!2026", None) is False

    assert validate_password_policy("short") != []
    assert validate_password_policy("aaaaaaaaaaaa") != []
    assert validate_password_policy("ValidLongPassword123!") == []


def test_jwt_create_decode_and_expiry() -> None:
    uid = uuid.uuid4()
    secret = VALID_SECRET.get_secret_value()
    token = create_access_token(uid, secret, expires_minutes=15)
    payload = decode_access_token(token, secret)
    assert payload.user_id == uid

    with pytest.raises(TokenError):
        decode_access_token(token, "wrong-secret-key-with-at-least-32-bytes!!")

    past = datetime.now(UTC) - timedelta(hours=2)
    expired = create_access_token(uid, secret, expires_minutes=5, now=past)
    with pytest.raises(TokenError):
        decode_access_token(expired, secret)


def test_fixed_window_rate_limiter() -> None:
    now = 100.0
    limiter = FixedWindowRateLimiter(clock=lambda: now)

    assert limiter.hit("ip1", limit=2, window_seconds=60).allowed is True
    assert limiter.hit("ip1", limit=2, window_seconds=60).allowed is True
    blocked = limiter.hit("ip1", limit=2, window_seconds=60)
    assert blocked.allowed is False
    assert blocked.retry_after_seconds == 60

    now = 161.0
    assert limiter.hit("ip1", limit=2, window_seconds=60).allowed is True


def test_log_redaction_masks_sensitive_keys() -> None:
    event = {
        "event": "user_login",
        "username": "alice",
        "password": "SuperSecretPassword",
        "nested": {"Authorization": "Bearer secret-jwt", "safe": "ok"},
    }
    redacted = redact_sensitive(None, "info", event)
    assert redacted["username"] == "alice"
    assert redacted["password"] == REDACTED
    assert redacted["nested"]["Authorization"] == REDACTED
    assert redacted["nested"]["safe"] == "ok"
