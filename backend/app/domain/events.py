"""The normalized event model shared by parsers, the simulator and detection rules.

This module is deliberately framework-free (no FastAPI, no SQLAlchemy). Parsers
produce `NormalizedEvent` objects and detection rules consume them. That keeps the
whole detection pipeline unit-testable with plain Python objects.

Type-specific details live in `fields`, using flat ECS-style dotted keys
(e.g. ``url.path``, ``dns.question.name``, ``process.command_line``).
"""

from __future__ import annotations

import hashlib
import ipaddress
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from app.domain.enums import EventOutcome, EventType, Severity

FieldValue = str | int | float | bool | None | list[str] | list[int]


@dataclass(slots=True)
class NormalizedEvent:
    timestamp: datetime
    event_type: EventType
    log_source: str
    raw_event: str
    event_action: str | None = None
    event_outcome: EventOutcome = EventOutcome.UNKNOWN
    severity: Severity = Severity.INFORMATIONAL
    source_ip: str | None = None
    destination_ip: str | None = None
    source_port: int | None = None
    destination_port: int | None = None
    protocol: str | None = None
    username: str | None = None
    hostname: str | None = None
    service: str | None = None
    fields: dict[str, FieldValue] = field(default_factory=dict)
    is_synthetic: bool = False
    event_id: uuid.UUID = field(default_factory=uuid.uuid4)

    def __post_init__(self) -> None:
        if self.timestamp.tzinfo is None:
            raise ValueError("NormalizedEvent.timestamp must be timezone-aware")
        self.timestamp = self.timestamp.astimezone(UTC)
        self.source_ip = canonical_ip(self.source_ip)
        self.destination_ip = canonical_ip(self.destination_ip)
        for port in (self.source_port, self.destination_port):
            if port is not None and not 0 <= port <= 65535:
                raise ValueError(f"Port out of range: {port}")

    @property
    def event_hash(self) -> str:
        """Content hash used for idempotent ingestion (same line, same source = same event)."""
        digest = hashlib.sha256()
        digest.update(self.log_source.encode("utf-8"))
        digest.update(b"\x1f")
        digest.update(self.raw_event.encode("utf-8", errors="replace"))
        return digest.hexdigest()

    def get(self, key: str, default: Any = None) -> Any:
        return self.fields.get(key, default)

    def to_document(self) -> dict[str, Any]:
        """Full normalized document stored in the `normalized_event` JSONB column."""
        doc: dict[str, Any] = {
            "@timestamp": self.timestamp.isoformat(),
            "event.type": self.event_type.value,
            "event.action": self.event_action,
            "event.outcome": self.event_outcome.value,
            "event.severity": self.severity.value,
            "log.source": self.log_source,
            "source.ip": self.source_ip,
            "source.port": self.source_port,
            "destination.ip": self.destination_ip,
            "destination.port": self.destination_port,
            "network.protocol": self.protocol,
            "user.name": self.username,
            "host.name": self.hostname,
            "service.name": self.service,
        }
        doc = {k: v for k, v in doc.items() if v is not None}
        doc.update(self.fields)
        if self.is_synthetic:
            doc["labels.synthetic"] = True
        return doc


def canonical_ip(value: str | None) -> str | None:
    """Validate and canonicalise an IP address string (raises ValueError if invalid)."""
    if value is None or value == "":
        return None
    return str(ipaddress.ip_address(value.strip()))


def is_private_ip(value: str | None) -> bool:
    if not value:
        return False
    try:
        return ipaddress.ip_address(value).is_private
    except ValueError:
        return False
