from __future__ import annotations

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import __version__
from app.api.deps import (
    CurrentUser,
    ViewerUser,
    get_client_ip,
    get_db,
    get_settings_dep,
    rate_limit,
)
from app.core.config import Settings
from app.core.errors import AuthenticationError, RateLimitExceededError, ServiceUnavailableError
from app.core.rate_limit import FixedWindowRateLimiter
from app.core.security import create_access_token
from app.models import User
from app.schemas.auth import LoginRequest, UserRead, UserSummary
from app.schemas.common import MessageResponse
from app.services.audit import record_audit
from app.services.users import authenticate, normalize_username

health_router = APIRouter(tags=["health"])
auth_router = APIRouter(prefix="/auth", tags=["auth"])
users_router = APIRouter(prefix="/users", tags=["users"])

_GENERIC_LOGIN_ERROR = "Invalid username or password"


@health_router.get("/health", summary="Liveness probe")
def health() -> dict[str, str]:
    return {"status": "ok", "version": __version__}


@health_router.get("/health/ready", summary="Readiness probe (database reachable)")
def readiness(db: Session = Depends(get_db)) -> dict[str, str]:
    try:
        db.execute(select(1))
    except Exception as exc:
        raise ServiceUnavailableError("Database is not reachable") from exc
    return {"status": "ready", "database": "ok"}


@auth_router.post(
    "/login",
    response_model=UserRead,
    dependencies=[Depends(rate_limit("login", "login_rate_limit_per_minute"))],
)
def login(
    body: LoginRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings_dep),
) -> User:
    client_ip = get_client_ip(request)
    username = normalize_username(body.username)

    # Second limiter keyed on the target account: slows distributed guessing
    # against one user that the per-IP limiter alone would miss.
    if settings.rate_limit_enabled:
        limiter: FixedWindowRateLimiter = request.app.state.rate_limiter
        result = limiter.hit(f"login-user:{username}", settings.login_rate_limit_per_minute, 60)
        if not result.allowed:
            raise RateLimitExceededError(result.retry_after_seconds)

    user = authenticate(db, username, body.password)
    if user is None:
        record_audit(
            db,
            action="auth.login_failed",
            target_type="user",
            target_id=username[:64],
            client_ip=client_ip,
        )
        db.commit()
        raise AuthenticationError(_GENERIC_LOGIN_ERROR)

    record_audit(db, action="auth.login", actor_id=user.id, client_ip=client_ip)
    db.commit()

    token = create_access_token(
        user.id, settings.secret_key.get_secret_value(), settings.access_token_expire_minutes
    )
    response.set_cookie(
        key=settings.session_cookie_name,
        value=token,
        max_age=settings.access_token_expire_minutes * 60,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="strict",
        path="/api",
    )
    return user


@auth_router.post("/logout", response_model=MessageResponse)
def logout(response: Response, settings: Settings = Depends(get_settings_dep)) -> MessageResponse:
    response.delete_cookie(
        settings.session_cookie_name,
        path="/api",
        httponly=True,
        secure=settings.cookie_secure,
        samesite="strict",
    )
    return MessageResponse(message="Logged out")


@auth_router.get("/me", response_model=UserRead)
def me(user: User = CurrentUser) -> User:
    return user


@users_router.get("", response_model=list[UserSummary])
def list_users(db: Session = Depends(get_db), _: User = ViewerUser) -> list[User]:
    """Active users (used to populate analyst assignment dropdowns)."""
    return list(db.scalars(select(User).where(User.is_active.is_(True)).order_by(User.username)))
