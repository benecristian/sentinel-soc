"""Pydantic request and response schemas for SOC domain resources."""

from __future__ import annotations

import ipaddress
import uuid
from datetime import datetime
from typing import Any

from pydantic import Field, field_validator

from app.domain.enums import (
    AlertStatus,
    EventOutcome,
    EventType,
    IncidentStatus,
    IngestionSourceKind,
    Severity,
    SimulationStatus,
    TimelineEntryType,
)
from app.ingestion.parsers import JsonEventPayload
from app.schemas.auth import UserSummary
from app.schemas.common import APIModel, StrictInput

# ---------------------------------------------------------------------------
# Events & Ingestion
# ---------------------------------------------------------------------------


class IngestBatchRequest(StrictInput):
    events: list[JsonEventPayload] = Field(min_length=1, max_length=1000)


class IngestionBatchRead(APIModel):
    id: uuid.UUID
    source_kind: IngestionSourceKind
    original_filename: str | None = None
    parser: str
    received_count: int
    accepted_count: int
    rejected_count: int
    duplicate_count: int
    ignored_count: int
    alerts_created: int
    alerts_updated: int
    events_start: datetime | None = None
    events_end: datetime | None = None
    error_samples: list[dict[str, Any]]
    started_at: datetime
    completed_at: datetime | None = None


class SecurityEventRead(APIModel):
    id: uuid.UUID
    ingestion_batch_id: uuid.UUID | None = None
    timestamp: datetime
    ingested_at: datetime
    event_type: EventType
    event_action: str | None = None
    event_outcome: EventOutcome
    severity: Severity
    source_ip: str | None = None
    destination_ip: str | None = None
    source_port: int | None = None
    destination_port: int | None = None
    protocol: str | None = None
    username: str | None = None
    hostname: str | None = None
    service: str | None = None
    log_source: str
    raw_event: str
    normalized_event: dict[str, Any]
    is_synthetic: bool

    @field_validator("source_ip", "destination_ip", mode="before")
    @classmethod
    def _ip_to_str(cls, v: object) -> str | None:
        return str(v) if v is not None else None


# ---------------------------------------------------------------------------
# Detection Rules
# ---------------------------------------------------------------------------


class RuleMitreLinkRead(APIModel):
    technique_id: str
    technique_name: str
    is_primary: bool


class DetectionRuleRead(APIModel):
    id: str
    name: str
    description: str
    category: str
    severity: Severity
    enabled: bool
    threshold: int
    time_window_seconds: int
    parameters: dict[str, Any]
    investigation_steps: list[str]
    remediation_steps: list[str]
    version: int
    updated_at: datetime
    mitre_techniques: list[RuleMitreLinkRead] = Field(default_factory=list)


class DetectionRuleUpdateRequest(StrictInput):
    enabled: bool | None = None
    severity: Severity | None = None
    threshold: int | None = Field(default=None, ge=1, le=100_000)
    time_window_seconds: int | None = Field(default=None, ge=10, le=86_400)
    parameters: dict[str, Any] | None = None

    @field_validator("parameters")
    @classmethod
    def _validate_parameters(cls, params: dict[str, Any] | None) -> dict[str, Any] | None:
        if params is None:
            return None
        if len(params) > 32:
            raise ValueError("Too many rule parameters")
        if "allowlist_ips" in params:
            raw_list = params["allowlist_ips"]
            if not isinstance(raw_list, list) or len(raw_list) > 200:
                raise ValueError("allowlist_ips must be a list of at most 200 IP/CIDR entries")
            for entry in raw_list:
                try:
                    ipaddress.ip_network(str(entry).strip(), strict=False)
                except ValueError as exc:
                    raise ValueError(f"Invalid IP/CIDR in allowlist_ips: {entry!r}") from exc
        return params


class DetectionRunRequest(StrictInput):
    hours: int = Field(default=24, ge=1, le=720)


# ---------------------------------------------------------------------------
# Alerts & Investigation Notes
# ---------------------------------------------------------------------------


class NoteCreateRequest(StrictInput):
    body: str = Field(min_length=1, max_length=10_000)


class InvestigationNoteRead(APIModel):
    id: uuid.UUID
    alert_id: uuid.UUID | None = None
    incident_id: uuid.UUID | None = None
    author: UserSummary | None = None
    body: str
    created_at: datetime


class AlertSummaryRead(APIModel):
    id: uuid.UUID
    reference: str
    rule_id: str
    rule_name: str
    severity: Severity
    status: AlertStatus
    title: str
    source_ip: str | None = None
    username: str | None = None
    hostname: str | None = None
    mitre_technique_id: str | None = None
    event_count: int
    first_seen: datetime
    last_seen: datetime
    assigned_to: uuid.UUID | None = None
    assignee: UserSummary | None = None
    created_at: datetime
    updated_at: datetime
    resolved_at: datetime | None = None

    @field_validator("source_ip", mode="before")
    @classmethod
    def _ip_to_str(cls, v: object) -> str | None:
        return str(v) if v is not None else None


class AlertDetailRead(AlertSummaryRead):
    description: str
    evidence: dict[str, Any]
    incident_id: uuid.UUID | None = None
    investigation_steps: list[str] = Field(default_factory=list)
    remediation_steps: list[str] = Field(default_factory=list)
    notes: list[InvestigationNoteRead] = Field(default_factory=list)


class AlertUpdateRequest(StrictInput):
    status: AlertStatus | None = None
    assigned_to: uuid.UUID | None = None
    note: str | None = Field(default=None, min_length=1, max_length=10_000)


# ---------------------------------------------------------------------------
# Incidents
# ---------------------------------------------------------------------------


class TimelineEntryRead(APIModel):
    id: uuid.UUID
    occurred_at: datetime
    entry_type: TimelineEntryType
    summary: str
    details: dict[str, Any]
    actor_id: uuid.UUID | None = None


class IncidentSummaryRead(APIModel):
    id: uuid.UUID
    reference: str
    title: str
    description: str
    severity: Severity
    status: IncidentStatus
    lead_analyst_id: uuid.UUID | None = None
    lead_analyst: UserSummary | None = None
    alert_count: int = 0
    created_at: datetime
    updated_at: datetime
    closed_at: datetime | None = None


class IncidentDetailRead(IncidentSummaryRead):
    recommended_actions: list[str]
    findings: str
    resolution_summary: str
    alerts: list[AlertSummaryRead]
    timeline: list[TimelineEntryRead]
    notes: list[InvestigationNoteRead]


class IncidentCreateRequest(StrictInput):
    title: str = Field(min_length=3, max_length=255)
    description: str = Field(default="", max_length=10_000)
    severity: Severity = Severity.HIGH
    lead_analyst_id: uuid.UUID | None = None
    alert_ids: list[uuid.UUID] = Field(default_factory=list, max_length=100)
    recommended_actions: list[str] = Field(default_factory=list, max_length=50)


class IncidentUpdateRequest(StrictInput):
    title: str | None = Field(default=None, min_length=3, max_length=255)
    description: str | None = Field(default=None, max_length=10_000)
    status: IncidentStatus | None = None
    severity: Severity | None = None
    lead_analyst_id: uuid.UUID | None = None
    findings: str | None = Field(default=None, max_length=20_000)
    resolution_summary: str | None = Field(default=None, max_length=20_000)
    recommended_actions: list[str] | None = Field(default=None, max_length=50)


class IncidentAttachAlertsRequest(StrictInput):
    alert_ids: list[uuid.UUID] = Field(min_length=1, max_length=100)


# ---------------------------------------------------------------------------
# Simulations
# ---------------------------------------------------------------------------


class ScenarioRead(APIModel):
    id: str
    name: str
    category: str
    description: str
    expected_rules: list[str]
    mitre_techniques: list[str]
    default_seed: int


class SimulationRunRequest(StrictInput):
    seed: int | None = Field(default=None, ge=1, le=2_147_483_647)


class SimulationRunRead(APIModel):
    id: uuid.UUID
    scenario_id: str
    status: SimulationStatus
    seed: int
    parameters: dict[str, Any]
    events_generated: int
    alerts_generated: int
    error: str | None = None
    started_at: datetime
    completed_at: datetime | None = None
