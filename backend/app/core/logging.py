"""Structured logging with credential redaction.

Why this matters in a SOC context: application logs are themselves security
telemetry, and they are often shipped to other systems with broader access.
Logging a password, session token or Authorization header turns the log
pipeline into a credential leak. The `redact_sensitive` processor masks such
values *before* any renderer sees them, regardless of who called the logger.
"""

from __future__ import annotations

import logging
import re
import sys
from collections.abc import Mapping, MutableMapping
from typing import Any

import structlog

REDACTED = "[REDACTED]"

_SENSITIVE_KEY_PATTERN = re.compile(
    r"(pass(word|wd)?|secret|token|authorization|cookie|api[_-]?key|session|credential)",
    re.IGNORECASE,
)
_MAX_DEPTH = 6


def _redact(value: Any, depth: int = 0) -> Any:
    if depth > _MAX_DEPTH:
        return value
    if isinstance(value, Mapping):
        return {
            key: (
                REDACTED
                if isinstance(key, str) and _SENSITIVE_KEY_PATTERN.search(key)
                else _redact(item, depth + 1)
            )
            for key, item in value.items()
        }
    if isinstance(value, list | tuple):
        return type(value)(_redact(item, depth + 1) for item in value)
    return value


def redact_sensitive(
    _logger: Any, _method_name: str, event_dict: MutableMapping[str, Any]
) -> MutableMapping[str, Any]:
    """structlog processor that masks values stored under sensitive keys."""
    for key in list(event_dict.keys()):
        if key == "event":
            continue
        if _SENSITIVE_KEY_PATTERN.search(key):
            event_dict[key] = REDACTED
        else:
            event_dict[key] = _redact(event_dict[key])
    return event_dict


def configure_logging(level: str = "INFO", json_logs: bool = False) -> None:
    """Configure structlog and route stdlib logging through the same output."""
    shared_processors: list[structlog.types.Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        redact_sensitive,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]
    renderer: structlog.types.Processor = (
        structlog.processors.JSONRenderer()
        if json_logs
        else structlog.dev.ConsoleRenderer(colors=False)
    )

    structlog.configure(
        processors=[*shared_processors, renderer],
        wrapper_class=structlog.make_filtering_bound_logger(logging.getLevelName(level)),
        logger_factory=structlog.PrintLoggerFactory(file=sys.stdout),
        cache_logger_on_first_use=False,
    )

    logging.basicConfig(level=level, format="%(message)s", stream=sys.stdout, force=True)
    # Our middleware emits a structured access log; avoid duplicate lines.
    logging.getLogger("uvicorn.access").disabled = True


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    return structlog.get_logger(name)  # type: ignore[no-any-return]
