"""Detection engine: loads windowed events, evaluates rules, and upserts alerts."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.detection.base import DetectionRuleContract, Finding, RuleConfig
from app.detection.rules import ALL_RULES
from app.domain.enums import AlertStatus, EventOutcome, EventType, Severity
from app.domain.events import FieldValue, NormalizedEvent
from app.models import Alert, DetectionRule, SecurityEvent, alert_events

_RESERVED_DOC_KEYS = frozenset(
    {
        "@timestamp",
        "event.type",
        "event.action",
        "event.outcome",
        "event.severity",
        "log.source",
        "source.ip",
        "source.port",
        "destination.ip",
        "destination.port",
        "network.protocol",
        "user.name",
        "host.name",
        "service.name",
        "labels.synthetic",
    }
)


@dataclass(slots=True)
class DetectionRunSummary:
    rules_evaluated: int = 0
    findings_count: int = 0
    alerts_created: int = 0
    alerts_updated: int = 0
    alerts: list[Alert] = field(default_factory=list)


def orm_event_to_normalized(row: SecurityEvent) -> NormalizedEvent:
    doc: dict[str, Any] = row.normalized_event or {}
    extra_fields: dict[str, FieldValue] = {
        k: v for k, v in doc.items() if k not in _RESERVED_DOC_KEYS
    }
    return NormalizedEvent(
        event_id=row.id,
        timestamp=row.timestamp,
        event_type=EventType(row.event_type),
        event_action=row.event_action,
        event_outcome=EventOutcome(row.event_outcome),
        severity=Severity(row.severity),
        source_ip=str(row.source_ip) if row.source_ip else None,
        destination_ip=str(row.destination_ip) if row.destination_ip else None,
        source_port=row.source_port,
        destination_port=row.destination_port,
        protocol=row.protocol,
        username=row.username,
        hostname=row.hostname,
        service=row.service,
        log_source=row.log_source,
        raw_event=row.raw_event,
        fields=extra_fields,
        is_synthetic=row.is_synthetic,
    )


def load_rule_configs(db: Session) -> dict[str, RuleConfig]:
    db_rows = {row.id: row for row in db.scalars(select(DetectionRule)).all()}
    configs: dict[str, RuleConfig] = {}
    for rule in ALL_RULES:
        meta = rule.metadata
        row = db_rows.get(meta.id)
        if row is None:
            configs[meta.id] = RuleConfig.from_metadata(meta)
        else:
            merged_params = {**meta.default_parameters, **(row.parameters or {})}
            configs[meta.id] = RuleConfig(
                enabled=row.enabled,
                severity=Severity(row.severity),
                threshold=row.threshold,
                time_window_seconds=row.time_window_seconds,
                parameters=merged_params,
            )
    return configs


def evaluate_pure(
    events: Sequence[NormalizedEvent],
    configs: dict[str, RuleConfig] | None = None,
    rules: Sequence[DetectionRuleContract] = ALL_RULES,
) -> list[Finding]:
    """Pure in-memory evaluation helper (used directly by unit tests)."""
    findings: list[Finding] = []
    for rule in rules:
        cfg = (configs or {}).get(rule.metadata.id) or RuleConfig.from_metadata(rule.metadata)
        if not cfg.enabled:
            continue
        findings.extend(rule.evaluate(events, cfg))
    return findings


def run_detection_for_time_range(
    db: Session,
    *,
    start_time: datetime,
    end_time: datetime,
    event_types: set[EventType] | None = None,
) -> DetectionRunSummary:
    configs = load_rule_configs(db)
    candidate_rules = [
        rule
        for rule in ALL_RULES
        if configs[rule.metadata.id].enabled
        and (event_types is None or bool(rule.event_types & event_types))
    ]
    if not candidate_rules:
        return DetectionRunSummary()

    max_window = max(configs[r.metadata.id].time_window_seconds for r in candidate_rules)
    padded_start = start_time - timedelta(seconds=max_window)
    padded_end = end_time + timedelta(seconds=max_window)

    needed_types = {et.value for rule in candidate_rules for et in rule.event_types}
    stmt = (
        select(SecurityEvent)
        .where(
            SecurityEvent.timestamp >= padded_start,
            SecurityEvent.timestamp <= padded_end,
            SecurityEvent.event_type.in_(needed_types),
        )
        .order_by(SecurityEvent.timestamp.asc())
    )
    rows = db.scalars(stmt).all()
    if not rows:
        return DetectionRunSummary(rules_evaluated=len(candidate_rules))

    normalized = [orm_event_to_normalized(r) for r in rows]

    summary = DetectionRunSummary(rules_evaluated=len(candidate_rules))
    for rule in candidate_rules:
        cfg = configs[rule.metadata.id]
        rule_findings = rule.evaluate(normalized, cfg)
        for finding in rule_findings:
            summary.findings_count += 1
            alert, created = _upsert_finding_alert(db, finding)
            if created:
                summary.alerts_created += 1
            else:
                summary.alerts_updated += 1
            summary.alerts.append(alert)

    db.flush()
    return summary


def _upsert_finding_alert(db: Session, finding: Finding) -> tuple[Alert, bool]:
    open_statuses = (AlertStatus.NEW.value, AlertStatus.INVESTIGATING.value)
    existing = db.scalar(
        select(Alert).where(
            Alert.dedup_key == finding.dedup_key,
            Alert.status.in_(open_statuses),
        )
    )

    if existing is None:
        alert = Alert(
            rule_id=finding.rule_id,
            rule_name=finding.rule_name,
            severity=finding.severity.value,
            status=AlertStatus.NEW.value,
            title=finding.title[:255],
            description=finding.description,
            source_ip=finding.source_ip,
            username=finding.username,
            hostname=finding.hostname,
            mitre_technique_id=finding.mitre_technique_id,
            evidence=finding.evidence,
            dedup_key=finding.dedup_key,
            event_count=len(finding.event_ids),
            first_seen=finding.first_seen,
            last_seen=finding.last_seen,
        )
        db.add(alert)
        db.flush()
        created = True
    else:
        alert = existing
        if finding.severity.rank > Severity(alert.severity).rank:
            alert.severity = finding.severity.value
        alert.title = finding.title[:255]
        alert.description = finding.description
        alert.evidence = finding.evidence
        alert.first_seen = min(alert.first_seen, finding.first_seen)
        alert.last_seen = max(alert.last_seen, finding.last_seen)
        created = False

    if finding.event_ids:
        link_rows = [
            {"alert_id": alert.id, "event_id": eid} for eid in dict.fromkeys(finding.event_ids)
        ]
        db.execute(pg_insert(alert_events).values(link_rows).on_conflict_do_nothing())
        total_linked = db.scalar(
            select(func.count())
            .select_from(alert_events)
            .where(alert_events.c.alert_id == alert.id)
        )
        alert.event_count = int(total_linked or len(finding.event_ids))

    return alert, created
