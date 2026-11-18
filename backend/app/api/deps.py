"""Shared FastAPI dependencies: settings, authentication, RBAC, CSRF and rate limits."""

from __future__ import annotations

from collections.abc import Callable

from fastapi import Depends, Request
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.errors import (
    AuthenticationError,
    CSRFError,
    PermissionDeniedError,
    RateLimitExceededError,
)
from app.core.rate_limit import FixedWindowRateLimiter
from app.core.security import CSRF_HEADER_NAME, CSRF_HEADER_VALUE, TokenError, decode_access_token
from app.db.session import get_db
from app.domain.enums import UserRole
from app.models import User

_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

__all__ = [
    "csrf_protect",
    "get_client_ip",
    "get_current_user",
    "get_db",
    "get_settings_dep",
    "rate_limit",
    "require_role",
]


def get_settings_dep(request: Request) -> Settings:
    settings: Settings = request.app.state.settings
    return settings


def get_client_ip(request: Request) -> str | None:
    # uvicorn resolves X-Forwarded-For only from trusted proxies (--forwarded-allow-ips),
    # so request.client reflects the real client without trusting arbitrary headers.
    return request.client.host if request.client else None


def csrf_protect(request: Request) -> None:
    """Require the custom CSRF header on every state-changing request."""
    if request.method in _SAFE_METHODS:
        return
    if request.headers.get(CSRF_HEADER_NAME) != CSRF_HEADER_VALUE:
        raise CSRFError()


def get_current_user(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings_dep),
) -> User:
    token = request.cookies.get(settings.session_cookie_name)
    if not token:
        raise AuthenticationError()
    try:
        payload = decode_access_token(token, settings.secret_key.get_secret_value())
    except TokenError as exc:
        raise AuthenticationError("Session is invalid or has expired") from exc

    user = db.get(User, payload.user_id)
    if user is None or not user.is_active:
        raise AuthenticationError("Session is invalid or has expired")
    request.state.user_id = user.id
    return user


def require_role(minimum: UserRole) -> Callable[..., User]:
    """Dependency factory enforcing a minimum role (viewer < analyst < admin)."""

    def _dependency(user: User = Depends(get_current_user)) -> User:
        if user.role_enum.level < minimum.level:
            raise PermissionDeniedError()
        return user

    return _dependency


def rate_limit(scope: str, setting_name: str, window_seconds: int = 60) -> Callable[..., None]:
    """Dependency factory: limit requests per client IP using a Settings attribute."""

    def _dependency(request: Request, settings: Settings = Depends(get_settings_dep)) -> None:
        if not settings.rate_limit_enabled:
            return
        limiter: FixedWindowRateLimiter = request.app.state.rate_limiter
        limit = int(getattr(settings, setting_name))
        result = limiter.hit(f"{scope}:{get_client_ip(request)}", limit, window_seconds)
        if not result.allowed:
            raise RateLimitExceededError(result.retry_after_seconds)

    return _dependency


CurrentUser = Depends(get_current_user)
ViewerUser = Depends(require_role(UserRole.VIEWER))
AnalystUser = Depends(require_role(UserRole.ANALYST))
AdminUser = Depends(require_role(UserRole.ADMIN))
