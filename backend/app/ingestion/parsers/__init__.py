"""Parser registry and format auto-detection."""

from __future__ import annotations

from collections.abc import Sequence

from app.ingestion.parsers.base import (
    IgnoredLine,
    LogParser,
    ParseContext,
    ParseError,
    safe_excerpt,
)
from app.ingestion.parsers.bind_query import BindQueryParser
from app.ingestion.parsers.iptables import IptablesParser
from app.ingestion.parsers.json_events import (
    JsonEventPayload,
    JsonEventsParser,
    payload_to_normalized,
)
from app.ingestion.parsers.linux_auth import LinuxAuthParser
from app.ingestion.parsers.web_access import WebAccessParser

_PARSERS: tuple[LogParser, ...] = (
    JsonEventsParser(),
    WebAccessParser(),
    IptablesParser(),
    BindQueryParser(),
    LinuxAuthParser(),
)

PARSERS_BY_NAME: dict[str, LogParser] = {p.name: p for p in _PARSERS}
SUPPORTED_FORMATS: tuple[str, ...] = ("auto", *PARSERS_BY_NAME.keys())


def get_parser(name: str) -> LogParser:
    parser = PARSERS_BY_NAME.get(name)
    if parser is None:
        raise ValueError(f"Unknown parser format: {name!r}")
    return parser


def detect_parser(lines: Sequence[str]) -> LogParser:
    """Inspect the first non-empty lines to pick a parser."""
    for line in lines[:25]:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        for parser in _PARSERS:
            if parser.matches(stripped):
                return parser
    raise ParseError("Could not automatically detect log format from the provided lines")


__all__ = [
    "PARSERS_BY_NAME",
    "SUPPORTED_FORMATS",
    "BindQueryParser",
    "IgnoredLine",
    "IptablesParser",
    "JsonEventPayload",
    "JsonEventsParser",
    "LinuxAuthParser",
    "LogParser",
    "ParseContext",
    "ParseError",
    "WebAccessParser",
    "detect_parser",
    "get_parser",
    "payload_to_normalized",
    "safe_excerpt",
]
