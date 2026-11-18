"""Parser contract and shared helpers (syslog header, timestamps)."""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta, tzinfo

from app.domain.events import NormalizedEvent


class ParseError(ValueError):
    """A line could not be parsed. The message is safe to show to users."""


class IgnoredLine(Exception):  # noqa: N818 - a control-flow signal, not an error
    """A well-formed line that carries no security-relevant information.

    Real auth logs contain plenty of benign noise (session bookkeeping, disconnect
    messages). Counting it as "rejected" would make ingestion stats misleading,
    so it is tracked separately as "ignored".
    """


@dataclass(frozen=True, slots=True)
class ParseContext:
    """Information parsers need that is not present in every log line."""

    reference_time: datetime = field(default_factory=lambda: datetime.now(UTC))
    # Syslog BSD timestamps carry no timezone; assume this one.
    default_timezone: tzinfo = UTC
    is_synthetic: bool = False


class LogParser(ABC):
    name: str
    description: str

    @abstractmethod
    def matches(self, line: str) -> bool:
        """Cheap heuristic used for format auto-detection."""

    @abstractmethod
    def parse(self, line: str, ctx: ParseContext) -> NormalizedEvent:
        """Parse one line or raise ParseError."""


# Month names are mapped explicitly: strptime's %b depends on the OS locale,
# which would make parsing behave differently on a non-English system.
MONTHS = {
    name: index
    for index, name in enumerate(
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"],
        start=1,
    )
}

# "Nov 16 10:15:32 host program[pid]: message"  or
# "2026-11-16T10:15:32.123456+00:00 host program[pid]: message" (rsyslog high-precision)
SYSLOG_HEADER = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}:\d{2}"
    r"|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:?\d{2})?)"
    r"\s+(?P<host>[A-Za-z0-9._-]{1,255})"
    r"\s+(?P<program>[A-Za-z0-9._/()-]{1,64}?)(?:\[(?P<pid>\d{1,10})\])?:\s?"
    r"(?P<message>.*)$"
)


@dataclass(frozen=True, slots=True)
class SyslogRecord:
    timestamp: datetime
    host: str
    program: str
    pid: int | None
    message: str


def parse_syslog_header(line: str, ctx: ParseContext) -> SyslogRecord:
    match = SYSLOG_HEADER.match(line)
    if not match:
        raise ParseError("Not a syslog line")
    return SyslogRecord(
        timestamp=parse_syslog_timestamp(match["ts"], ctx),
        host=match["host"],
        program=match["program"],
        pid=int(match["pid"]) if match["pid"] else None,
        message=match["message"],
    )


def parse_syslog_timestamp(value: str, ctx: ParseContext) -> datetime:
    if value[0].isdigit():
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ParseError("Invalid ISO-8601 timestamp") from exc
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=ctx.default_timezone)

    # BSD format has no year: assume the reference year, but if that would put
    # the event more than a day in the future (e.g. a December log ingested in
    # January), it belongs to the previous year.
    try:
        month = MONTHS[value[0:3]]
        day = int(value[4:6])
        hour, minute, second = (int(part) for part in value[7:15].split(":"))
        reference = ctx.reference_time.astimezone(ctx.default_timezone)
        parsed = datetime(
            reference.year, month, day, hour, minute, second, tzinfo=ctx.default_timezone
        )
    except (KeyError, ValueError) as exc:
        raise ParseError("Invalid syslog timestamp") from exc
    if parsed > reference + timedelta(days=1):
        parsed = parsed.replace(year=parsed.year - 1)
    return parsed


_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def safe_excerpt(text: str, limit: int = 200) -> str:
    """Truncate and neutralise control characters for error samples."""
    cleaned = _CONTROL_CHARS.sub("?", text)
    return cleaned if len(cleaned) <= limit else cleaned[:limit] + "..."
