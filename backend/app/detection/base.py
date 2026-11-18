"""Core types and protocol for detection rules.

Every detection rule is a pure function of `(events, config) -> list[Finding]`.
Rules never import SQLAlchemy or FastAPI, which makes them fast and trivial to
unit-test with synthetic events.
"""

from __future__ import annotations

import hashlib
import uuid
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol

from app.domain.enums import EventType, Severity
from app.domain.events import NormalizedEvent


@dataclass(frozen=True, slots=True)
class MitreMapping:
    technique_id: str
    is_primary: bool = False


@dataclass(frozen=True, slots=True)
class RuleMetadata:
    id: str
    name: str
    description: str
    category: str
    default_severity: Severity
    default_threshold: int
    default_time_window_seconds: int
    default_parameters: dict[str, Any]
    mitre_mappings: tuple[MitreMapping, ...]
    investigation_steps: tuple[str, ...]
    remediation_steps: tuple[str, ...]

    @property
    def primary_technique_id(self) -> str:
        for mapping in self.mitre_mappings:
            if mapping.is_primary:
                return mapping.technique_id
        return self.mitre_mappings[0].technique_id


@dataclass(frozen=True, slots=True)
class RuleConfig:
    enabled: bool
    severity: Severity
    threshold: int
    time_window_seconds: int
    parameters: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_metadata(cls, meta: RuleMetadata) -> RuleConfig:
        return cls(
            enabled=True,
            severity=meta.default_severity,
            threshold=meta.default_threshold,
            time_window_seconds=meta.default_time_window_seconds,
            parameters=dict(meta.default_parameters),
        )


@dataclass(slots=True)
class Finding:
    rule_id: str
    rule_name: str
    severity: Severity
    group_key: str
    title: str
    description: str
    mitre_technique_id: str
    evidence: dict[str, Any]
    event_ids: list[uuid.UUID]
    first_seen: datetime
    last_seen: datetime
    source_ip: str | None = None
    username: str | None = None
    hostname: str | None = None

    @property
    def dedup_key(self) -> str:
        return compute_dedup_key(self.rule_id, self.group_key)


def compute_dedup_key(rule_id: str, group_key: str) -> str:
    return hashlib.sha256(f"{rule_id}:{group_key}".encode()).hexdigest()


class DetectionRuleContract(Protocol):
    metadata: RuleMetadata
    event_types: frozenset[EventType]

    def evaluate(self, events: Sequence[NormalizedEvent], config: RuleConfig) -> list[Finding]: ...
