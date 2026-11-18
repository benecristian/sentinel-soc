"""Test builders for NormalizedEvent objects."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from app.domain.enums import EventOutcome, EventType, Severity
from app.domain.events import FieldValue, NormalizedEvent

BASE_TIME = datetime(2026, 11, 16, 12, 0, 0, tzinfo=UTC)


def make_event(
    *,
    timestamp: datetime = BASE_TIME,
    event_type: EventType = EventType.AUTHENTICATION,
    event_action: str = "ssh_login",
    event_outcome: EventOutcome = EventOutcome.FAILURE,
    severity: Severity = Severity.LOW,
    source_ip: str | None = "203.0.113.10",
    destination_ip: str | None = "10.0.1.10",
    source_port: int | None = 50000,
    destination_port: int | None = 22,
    protocol: str | None = "ssh",
    username: str | None = "root",
    hostname: str | None = "srv-01",
    service: str | None = "sshd",
    log_source: str = "linux_auth",
    raw_event: str | None = None,
    fields: dict[str, FieldValue] | None = None,
    seq: int = 0,
) -> NormalizedEvent:
    raw = raw_event or (
        f"{timestamp.isoformat()} {hostname} {service}: {event_action} "
        f"{event_outcome.value} src={source_ip} dst={destination_ip}:{destination_port} "
        f"user={username} seq={seq}"
    )
    extra: dict[str, Any] = dict(fields or {})
    return NormalizedEvent(
        timestamp=timestamp,
        event_type=event_type,
        event_action=event_action,
        event_outcome=event_outcome,
        severity=severity,
        source_ip=source_ip,
        destination_ip=destination_ip,
        source_port=source_port,
        destination_port=destination_port,
        protocol=protocol,
        username=username,
        hostname=hostname,
        service=service,
        log_source=log_source,
        raw_event=raw,
        fields=extra,
        is_synthetic=True,
    )
