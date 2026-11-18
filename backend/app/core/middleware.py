"""ASGI middleware: request correlation, access logging and security headers.

Implemented as pure ASGI middleware rather than `BaseHTTPMiddleware` so it does
not buffer streaming responses, such as PDF report downloads.
"""

from __future__ import annotations

import re
import time
import uuid

import structlog
from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.logging import get_logger

logger = get_logger("sentinel.access")

REQUEST_ID_HEADER = "X-Request-ID"
# Accept a caller-supplied request id only if it is short and harmless.
# This prevents header and log injection through the correlation id.
_SAFE_REQUEST_ID = re.compile(r"^[A-Za-z0-9\-]{8,64}$")

# Swagger UI / ReDoc pages need inline scripts and the CDN, so the strict API CSP
# does not apply to them. They can be disabled entirely via ENABLE_API_DOCS=false.
_DOCS_PATHS = ("/api/docs", "/api/redoc")

_SECURITY_HEADERS: dict[str, str] = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}
_API_CSP = "default-src 'none'; frame-ancestors 'none'"


class RequestContextMiddleware:
    """Assigns a request id, binds it to log context and emits an access log line."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        incoming = _header(scope, REQUEST_ID_HEADER.lower())
        request_id = incoming if incoming and _SAFE_REQUEST_ID.match(incoming) else uuid.uuid4().hex
        scope.setdefault("state", {})["request_id"] = request_id

        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(request_id=request_id)

        started = time.perf_counter()
        status_code = 500

        async def send_wrapper(message: Message) -> None:
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message["status"]
                MutableHeaders(scope=message)[REQUEST_ID_HEADER] = request_id
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            client = scope.get("client")
            logger.info(
                "http_request",
                method=scope.get("method"),
                path=scope.get("path"),
                status=status_code,
                duration_ms=round((time.perf_counter() - started) * 1000, 2),
                client_ip=client[0] if client else None,
            )
            structlog.contextvars.clear_contextvars()


class SecurityHeadersMiddleware:
    """Adds defensive HTTP response headers to every response."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path: str = scope.get("path", "")
        is_docs = path.startswith(_DOCS_PATHS)

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                for name, value in _SECURITY_HEADERS.items():
                    headers.setdefault(name, value)
                if not is_docs:
                    headers.setdefault("Content-Security-Policy", _API_CSP)
                    headers.setdefault("Cache-Control", "no-store")
            await send(message)

        await self.app(scope, receive, send_wrapper)


def _header(scope: Scope, name: str) -> str | None:
    for key, value in scope.get("headers", []):
        if key.decode("latin-1").lower() == name:
            return str(value.decode("latin-1"))
    return None
