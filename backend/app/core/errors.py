"""Application exceptions and the consistent JSON error envelope.

Every error leaving the API has the same shape::

    {"error": {"code": "...", "message": "...", "details": [...], "request_id": "..."}}

Security properties:
* Unhandled exceptions return a generic 500. Stack traces, SQL statements and
  driver messages are logged server-side only (correlated via request_id).
* Validation errors never echo the submitted input back. A rejected login
  payload must not reflect the password in the response.
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.logging import get_logger

logger = get_logger(__name__)


class AppError(Exception):
    status_code: int = 400
    code: str = "bad_request"
    message: str = "Bad request"

    def __init__(
        self,
        message: str | None = None,
        *,
        details: list[dict[str, Any]] | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.message = message or self.message
        self.details = details or []
        self.headers = headers or {}
        super().__init__(self.message)


class AuthenticationError(AppError):
    status_code = 401
    code = "authentication_required"
    message = "Authentication required"


class PermissionDeniedError(AppError):
    status_code = 403
    code = "permission_denied"
    message = "You do not have permission to perform this action"


class CSRFError(AppError):
    status_code = 403
    code = "csrf_check_failed"
    message = "Missing or invalid CSRF protection header"


class NotFoundError(AppError):
    status_code = 404
    code = "not_found"
    message = "Resource not found"


class ConflictError(AppError):
    status_code = 409
    code = "conflict"
    message = "The request conflicts with the current state of the resource"


class InvalidStateTransitionError(ConflictError):
    code = "invalid_state_transition"
    message = "This status transition is not allowed"


class PayloadTooLargeError(AppError):
    status_code = 413
    code = "payload_too_large"
    message = "Payload too large"


class UnsupportedMediaTypeError(AppError):
    status_code = 415
    code = "unsupported_media_type"
    message = "Unsupported file type"


class ValidationFailedError(AppError):
    status_code = 422
    code = "validation_error"
    message = "Request validation failed"


class RateLimitExceededError(AppError):
    status_code = 429
    code = "rate_limited"
    message = "Too many requests. Please retry later."

    def __init__(self, retry_after_seconds: int) -> None:
        super().__init__(headers={"Retry-After": str(max(1, retry_after_seconds))})


class ServiceUnavailableError(AppError):
    status_code = 503
    code = "service_unavailable"
    message = "Service temporarily unavailable"


def _request_id(request: Request) -> str | None:
    return getattr(request.state, "request_id", None)


def error_response(
    request: Request,
    *,
    status_code: int,
    code: str,
    message: str,
    details: list[dict[str, Any]] | None = None,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={
            "error": {
                "code": code,
                "message": message,
                "details": details or [],
                "request_id": _request_id(request),
            }
        },
        headers=headers,
    )


def _sanitize_validation_errors(errors: list[Any]) -> list[dict[str, Any]]:
    """Keep location/message/type; drop `input`, `ctx` and `url` (may echo secrets)."""
    sanitized: list[dict[str, Any]] = []
    for err in errors:
        sanitized.append(
            {
                "loc": [str(part) for part in err.get("loc", [])],
                "msg": str(err.get("msg", "Invalid value")),
                "type": str(err.get("type", "value_error")),
            }
        )
    return sanitized


_HTTP_CODE_NAMES = {
    400: "bad_request",
    401: "authentication_required",
    403: "permission_denied",
    404: "not_found",
    405: "method_not_allowed",
    413: "payload_too_large",
    415: "unsupported_media_type",
}


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(AppError)
    async def _app_error(request: Request, exc: AppError) -> JSONResponse:
        return error_response(
            request,
            status_code=exc.status_code,
            code=exc.code,
            message=exc.message,
            details=exc.details,
            headers=exc.headers,
        )

    @app.exception_handler(RequestValidationError)
    async def _validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        return error_response(
            request,
            status_code=422,
            code="validation_error",
            message="Request validation failed",
            details=_sanitize_validation_errors(list(exc.errors())),
        )

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        message = exc.detail if isinstance(exc.detail, str) else "HTTP error"
        return error_response(
            request,
            status_code=exc.status_code,
            code=_HTTP_CODE_NAMES.get(exc.status_code, "http_error"),
            message=message,
            headers=getattr(exc, "headers", None),
        )

    @app.exception_handler(Exception)
    async def _unhandled_error(request: Request, exc: Exception) -> JSONResponse:
        logger.exception(
            "unhandled_exception", path=request.url.path, error_type=type(exc).__name__
        )
        return error_response(
            request,
            status_code=500,
            code="internal_error",
            message="An unexpected error occurred",
        )
