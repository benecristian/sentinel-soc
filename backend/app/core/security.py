"""Password hashing, session tokens and CSRF protection.

Choices and rationale
---------------------
* **Argon2id** (argon2-cffi defaults, RFC 9106 parameters): memory-hard, the
  algorithm recommended by the OWASP Password Storage Cheat Sheet.
* **Constant-work login**: when a username does not exist we still run a hash
  verification against a dummy hash, so response timing does not reveal which
  usernames are valid (user-enumeration defence).
* **JWT (HS256)** with an explicit algorithm allow-list on decode. This blocks
  the classic `alg: none` / algorithm-confusion attacks. Required claims are
  enforced. The token carries only the user id; role and active status are
  re-read from the database on every request so revocations apply immediately.
* **CSRF**: the session cookie is SameSite=Strict, and state-changing requests
  must also carry a custom header. Browsers cannot attach custom headers to
  cross-site requests without a CORS pre-flight, which our CORS allow-list
  rejects.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

JWT_ALGORITHM = "HS256"
TOKEN_TYPE_ACCESS = "access"  # noqa: S105 - token type label, not a secret
CSRF_HEADER_NAME = "X-Requested-With"
CSRF_HEADER_VALUE = "SentinelSOC"

PASSWORD_MIN_LENGTH = 12
PASSWORD_MAX_LENGTH = 128

_hasher = PasswordHasher()
# Pre-computed hash used to equalise timing when the user does not exist.
_DUMMY_HASH = _hasher.hash("sentinel-dummy-password-for-timing-equalisation")


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str | None) -> bool:
    """Verify a password. Always performs one Argon2 verification."""
    try:
        return _hasher.verify(password_hash or _DUMMY_HASH, password) and password_hash is not None
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def password_needs_rehash(password_hash: str) -> bool:
    return _hasher.check_needs_rehash(password_hash)


def validate_password_policy(password: str) -> list[str]:
    """NIST SP 800-63B style policy: length over complexity rules."""
    problems: list[str] = []
    if len(password) < PASSWORD_MIN_LENGTH:
        problems.append(f"Password must be at least {PASSWORD_MIN_LENGTH} characters long")
    if len(password) > PASSWORD_MAX_LENGTH:
        problems.append(f"Password must be at most {PASSWORD_MAX_LENGTH} characters long")
    if password.strip() != password:
        problems.append("Password must not start or end with whitespace")
    if len(set(password)) < 4:
        problems.append("Password is too repetitive")
    return problems


class TokenError(Exception):
    """Raised when a session token is missing, invalid or expired."""


@dataclass(frozen=True, slots=True)
class TokenPayload:
    user_id: uuid.UUID
    issued_at: datetime
    expires_at: datetime
    token_id: str


def create_access_token(
    user_id: uuid.UUID,
    secret_key: str,
    expires_minutes: int,
    *,
    now: datetime | None = None,
) -> str:
    issued = now or datetime.now(UTC)
    claims = {
        "sub": str(user_id),
        "type": TOKEN_TYPE_ACCESS,
        "iat": int(issued.timestamp()),
        "exp": int((issued + timedelta(minutes=expires_minutes)).timestamp()),
        "jti": uuid.uuid4().hex,
    }
    return jwt.encode(claims, secret_key, algorithm=JWT_ALGORITHM)


def decode_access_token(token: str, secret_key: str) -> TokenPayload:
    try:
        claims = jwt.decode(
            token,
            secret_key,
            algorithms=[JWT_ALGORITHM],
            options={"require": ["sub", "exp", "iat", "jti", "type"]},
        )
    except jwt.PyJWTError as exc:
        raise TokenError("Invalid or expired token") from exc

    if claims.get("type") != TOKEN_TYPE_ACCESS:
        raise TokenError("Unexpected token type")
    try:
        user_id = uuid.UUID(str(claims["sub"]))
    except ValueError as exc:
        raise TokenError("Invalid subject") from exc

    return TokenPayload(
        user_id=user_id,
        issued_at=datetime.fromtimestamp(int(claims["iat"]), UTC),
        expires_at=datetime.fromtimestamp(int(claims["exp"]), UTC),
        token_id=str(claims["jti"]),
    )
