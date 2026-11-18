"""User management services (creation, authentication)."""

from __future__ import annotations

import re
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import (
    hash_password,
    password_needs_rehash,
    validate_password_policy,
    verify_password,
)
from app.domain.enums import UserRole
from app.models import User

USERNAME_PATTERN = re.compile(r"^[a-z0-9._-]{3,64}$")


class UserCreationError(ValueError):
    pass


def normalize_username(username: str) -> str:
    return username.strip().lower()


def create_user(
    db: Session,
    *,
    username: str,
    password: str,
    role: UserRole,
    display_name: str | None = None,
) -> User:
    username = normalize_username(username)
    if not USERNAME_PATTERN.match(username):
        raise UserCreationError("Username must be 3-64 characters: a-z, 0-9, '.', '_' or '-'")
    problems = validate_password_policy(password)
    if problems:
        raise UserCreationError("; ".join(problems))
    if db.scalar(select(User.id).where(User.username == username)) is not None:
        raise UserCreationError(f"User {username!r} already exists")

    user = User(
        username=username,
        display_name=display_name or username,
        password_hash=hash_password(password),
        role=role.value,
    )
    db.add(user)
    db.flush()
    return user


def authenticate(db: Session, username: str, password: str) -> User | None:
    """Return the user on valid credentials, else None (constant-work)."""
    user = db.scalar(select(User).where(User.username == normalize_username(username)))
    password_ok = verify_password(password, user.password_hash if user else None)
    if user is None or not password_ok or not user.is_active:
        return None
    if password_needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)
    user.last_login_at = datetime.now(UTC)
    return user
