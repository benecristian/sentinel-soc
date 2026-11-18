"""Parser for structured JSON / JSON Lines security events."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.domain.enums import EventOutcome, EventType, Severity
from app.domain.events import FieldValue, NormalizedEvent
from app.ingestion.parsers.base import LogParser, ParseContext, ParseError

_ALLOWED_FIELD_TYPES = (str, int, float, bool, type(None))


class JsonEventPayload(BaseModel):
    """Schema accepted by both the JSONL file parser and `POST /events/ingest`."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    timestamp: datetime
    event_type: EventType
    event_action: str | None = Field(default=None, max_length=64)
    event_outcome: EventOutcome = EventOutcome.UNKNOWN
    severity: Severity = Severity.INFORMATIONAL
    source_ip: str | None = Field(default=None, max_length=45)
    destination_ip: str | None = Field(default=None, max_length=45)
    source_port: int | None = Field(default=None, ge=0, le=65535)
    destination_port: int | None = Field(default=None, ge=0, le=65535)
    protocol: str | None = Field(default=None, max_length=16)
    username: str | None = Field(default=None, max_length=256)
    hostname: str | None = Field(default=None, max_length=255)
    service: str | None = Field(default=None, max_length=64)
    raw_event: str | None = Field(default=None, max_length=8192)
    fields: dict[str, Any] = Field(default_factory=dict)


def payload_to_normalized(
    payload: JsonEventPayload,
    *,
    raw_fallback: str,
    ctx: ParseContext,
    log_source: str = "json",
) -> NormalizedEvent:
    ts = payload.timestamp
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=ctx.default_timezone)
    ts = ts.astimezone(UTC)

    cleaned_fields: dict[str, FieldValue] = {}
    if len(payload.fields) > 64:
        raise ParseError("Too many custom fields (maximum 64)")
    for key, val in payload.fields.items():
        if not key or len(key) > 64:
            raise ParseError("Invalid field key length")
        if isinstance(val, _ALLOWED_FIELD_TYPES):
            cleaned_fields[key] = val[:2048] if isinstance(val, str) else val
        elif isinstance(val, list) and all(isinstance(x, str | int) for x in val):
            cleaned_fields[key] = val[:50]
        else:
            raise ParseError(f"Unsupported value type for field {key!r}")

    try:
        return NormalizedEvent(
            timestamp=ts,
            event_type=payload.event_type,
            event_action=payload.event_action or payload.event_type.value,
            event_outcome=payload.event_outcome,
            severity=payload.severity,
            log_source=log_source,
            raw_event=(payload.raw_event or raw_fallback)[:8192],
            source_ip=payload.source_ip,
            destination_ip=payload.destination_ip,
            source_port=payload.source_port,
            destination_port=payload.destination_port,
            protocol=payload.protocol.lower() if payload.protocol else None,
            username=payload.username,
            hostname=payload.hostname,
            service=payload.service,
            fields=cleaned_fields,
            is_synthetic=ctx.is_synthetic,
        )
    except ValueError as exc:
        raise ParseError(str(exc)) from exc


class JsonEventsParser(LogParser):
    name = "json"
    description = "Structured JSON Lines (JSONL) security events"

    def matches(self, line: str) -> bool:
        stripped = line.lstrip()
        return stripped.startswith("{") and stripped.endswith("}")

    def parse(self, line: str, ctx: ParseContext) -> NormalizedEvent:
        try:
            data = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ParseError("Malformed JSON record") from exc
        if not isinstance(data, dict):
            raise ParseError("JSON record must be an object")
        try:
            payload = JsonEventPayload.model_validate(data)
        except ValidationError as exc:
            errs = exc.errors()
            if errs:
                loc = ".".join(str(p) for p in errs[0].get("loc", ()))
                msg = str(errs[0].get("msg", "validation error"))
            else:
                loc, msg = "body", "validation error"
            raise ParseError(f"Invalid JSON event ({loc}: {msg})") from exc

        return payload_to_normalized(payload, raw_fallback=line, ctx=ctx, log_source=self.name)
