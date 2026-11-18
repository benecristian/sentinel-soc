"""FastAPI application factory."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import __version__
from app.api.deps import csrf_protect
from app.api.v1 import api_router
from app.core.config import Settings, get_settings
from app.core.errors import register_exception_handlers
from app.core.logging import configure_logging
from app.core.middleware import RequestContextMiddleware, SecurityHeadersMiddleware
from app.core.rate_limit import FixedWindowRateLimiter
from app.core.security import CSRF_HEADER_NAME
from app.db.session import build_engine, build_session_factory

API_PREFIX = "/api/v1"


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    try:
        yield
    finally:
        engine = getattr(app.state, "engine", None)
        if engine is not None:
            engine.dispose()


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings.log_level, settings.log_json)

    app = FastAPI(
        title="SENTINEL SOC API",
        version=__version__,
        description=(
            "Security monitoring, threat detection and incident response platform. "
            "Demonstration data produced by the simulator is synthetic."
        ),
        docs_url="/api/docs" if settings.enable_api_docs else None,
        redoc_url="/api/redoc" if settings.enable_api_docs else None,
        openapi_url="/api/openapi.json" if settings.enable_api_docs else None,
        dependencies=[Depends(csrf_protect)],
        lifespan=_lifespan,
    )

    engine = build_engine(settings.database_url.get_secret_value())
    app.state.settings = settings
    app.state.engine = engine
    app.state.session_factory = build_session_factory(engine)
    app.state.rate_limiter = FixedWindowRateLimiter()

    register_exception_handlers(app)

    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origins,
            allow_credentials=True,
            allow_methods=["GET", "POST", "PATCH", "DELETE"],
            allow_headers=["Content-Type", CSRF_HEADER_NAME, "X-Request-ID"],
            expose_headers=["X-Request-ID", "Retry-After", "Content-Disposition"],
            max_age=600,
        )
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RequestContextMiddleware)

    app.include_router(api_router, prefix=API_PREFIX)
    app.include_router(api_router, prefix="/api", include_in_schema=False)
    return app
