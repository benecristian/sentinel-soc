"""Parser for Nginx / Apache Combined Log Format.

Example line:
198.51.100.42 - alice [16/Nov/2026:10:15:32 +0000] "GET /login?next=/admin HTTP/1.1" 200 1420 "https://portal.example.test/" "Mozilla/5.0"
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

from app.domain.enums import EventOutcome, EventType, Severity
from app.domain.events import FieldValue, NormalizedEvent
from app.ingestion.parsers.base import MONTHS, LogParser, ParseContext, ParseError

COMBINED_LOG_RE = re.compile(
    r"^(?P<ip>[0-9a-fA-F.:]{2,45})\s+"
    r"(?P<ident>\S+)\s+"
    r"(?P<user>\S+)\s+"
    r"\[(?P<ts>\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4})\]\s+"
    r'"(?P<request>[^"]*)"\s+'
    r"(?P<status>\d{3})\s+"
    r"(?P<bytes>\d+|-)"
    r'(?:\s+"(?P<referrer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
    r"\s*$"
)


def _parse_clf_timestamp(value: str) -> datetime:
    """Parse '16/Nov/2026:10:15:32 +0000' without depending on OS locale."""
    try:
        day = int(value[0:2])
        month = MONTHS[value[3:6]]
        year = int(value[7:11])
        hour = int(value[12:14])
        minute = int(value[15:17])
        second = int(value[18:20])
        tz_sign = -1 if value[21] == "-" else 1
        tz_hours = int(value[22:24])
        tz_minutes = int(value[24:26])
        tz = timezone(tz_sign * timedelta(hours=tz_hours, minutes=tz_minutes))
        return datetime(year, month, day, hour, minute, second, tzinfo=tz)
    except (KeyError, ValueError, IndexError) as exc:
        raise ParseError("Invalid web access timestamp") from exc


class WebAccessParser(LogParser):
    name = "web_access"
    description = "Nginx / Apache HTTP access log (Combined Log Format)"

    def matches(self, line: str) -> bool:
        return bool(COMBINED_LOG_RE.match(line))

    def parse(self, line: str, ctx: ParseContext) -> NormalizedEvent:
        m = COMBINED_LOG_RE.match(line)
        if not m:
            raise ParseError("Line does not match Combined Log Format")

        timestamp = _parse_clf_timestamp(m["ts"])
        request_line = m["request"]
        parts = request_line.split(" ")
        if len(parts) == 3:
            method, raw_target, version = parts
        elif len(parts) == 2:
            method, raw_target = parts
            version = "HTTP/1.0"
        else:
            raise ParseError("Malformed HTTP request line")

        method = method.upper()[:16]
        if not method.isalpha():
            raise ParseError("Invalid HTTP method")

        split_target = urlsplit(raw_target)
        url_path = split_target.path or "/"
        url_query = split_target.query

        status_code = int(m["status"])
        if not 100 <= status_code <= 599:
            raise ParseError("HTTP status code out of range")

        bytes_raw = m["bytes"]
        body_bytes = int(bytes_raw) if bytes_raw and bytes_raw != "-" else 0
        username = None if m["user"] in ("-", "") else m["user"][:256]
        referrer = m["referrer"] if m["referrer"] and m["referrer"] != "-" else None
        user_agent = m["ua"] if m["ua"] is not None and m["ua"] != "-" else ""

        outcome = EventOutcome.SUCCESS if status_code < 400 else EventOutcome.FAILURE
        severity = Severity.INFORMATIONAL
        if status_code >= 500 or status_code in (401, 403):
            severity = Severity.LOW

        fields: dict[str, FieldValue] = {
            "http.request.method": method,
            "http.version": version[:16],
            "http.response.status_code": status_code,
            "http.response.body.bytes": body_bytes,
            "url.original": raw_target[:2048],
            "url.path": url_path[:2048],
            "user_agent.original": user_agent[:1024],
        }
        if url_query:
            fields["url.query"] = url_query[:2048]
        if referrer:
            fields["http.request.referrer"] = referrer[:1024]

        try:
            return NormalizedEvent(
                timestamp=timestamp,
                event_type=EventType.HTTP_REQUEST,
                event_action="http_request",
                event_outcome=outcome,
                severity=severity,
                log_source=self.name,
                raw_event=line,
                source_ip=m["ip"],
                protocol="http",
                username=username,
                service="http",
                is_synthetic=ctx.is_synthetic,
                fields=fields,
            )
        except ValueError as exc:
            raise ParseError(f"Invalid field in web log: {exc}") from exc
