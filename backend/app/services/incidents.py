"""Incident management, alert grouping, state machine and timeline tracking."""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import UTC, datetime

from sqlalchemy import delete, func, or_, select
from sqlalchemy.orm import Session, selectinload

from app.core.errors import (
    ConflictError,
    InvalidStateTransitionError,
    NotFoundError,
)
from app.domain.enums import (
    AlertStatus,
    IncidentStatus,
    Severity,
    TimelineEntryType,
)
from app.hunting.queries import escape_like
from app.models import (
    Alert,
    DetectionRule,
    Incident,
    IncidentAlert,
    IncidentTimelineEntry,
    InvestigationNote,
    User,
)
from app.services.audit import record_audit

ALLOWED_INCIDENT_TRANSITIONS: dict[IncidentStatus, frozenset[IncidentStatus]] = {
    IncidentStatus.OPEN: frozenset(
        {
            IncidentStatus.INVESTIGATING,
            IncidentStatus.CONTAINMENT,
            IncidentStatus.CLOSED,
        }
    ),
    IncidentStatus.INVESTIGATING: frozenset(
        {
            IncidentStatus.CONTAINMENT,
            IncidentStatus.ERADICATION,
            IncidentStatus.RECOVERY,
            IncidentStatus.CLOSED,
        }
    ),
    IncidentStatus.CONTAINMENT: frozenset(
        {
            IncidentStatus.INVESTIGATING,
            IncidentStatus.ERADICATION,
            IncidentStatus.RECOVERY,
            IncidentStatus.CLOSED,
        }
    ),
    IncidentStatus.ERADICATION: frozenset(
        {
            IncidentStatus.INVESTIGATING,
            IncidentStatus.CONTAINMENT,
            IncidentStatus.RECOVERY,
            IncidentStatus.CLOSED,
        }
    ),
    IncidentStatus.RECOVERY: frozenset(
        {
            IncidentStatus.INVESTIGATING,
            IncidentStatus.CONTAINMENT,
            IncidentStatus.ERADICATION,
            IncidentStatus.CLOSED,
        }
    ),
    IncidentStatus.CLOSED: frozenset({IncidentStatus.INVESTIGATING}),
}


def get_incident_or_404(db: Session, incident_id: uuid.UUID) -> Incident:
    incident = db.scalar(
        select(Incident)
        .where(Incident.id == incident_id)
        .options(
            selectinload(Incident.lead_analyst),
            selectinload(Incident.alert_links),
            selectinload(Incident.timeline),
        )
    )
    if incident is None:
        raise NotFoundError("Incident not found")
    return incident


def list_incidents_page(
    db: Session,
    *,
    status: IncidentStatus | None = None,
    severity: Severity | None = None,
    lead_analyst_id: uuid.UUID | None = None,
    q: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[Incident], int]:
    stmt = select(Incident).options(
        selectinload(Incident.lead_analyst), selectinload(Incident.alert_links)
    )
    if status is not None:
        stmt = stmt.where(Incident.status == status.value)
    if severity is not None:
        stmt = stmt.where(Incident.severity == severity.value)
    if lead_analyst_id is not None:
        stmt = stmt.where(Incident.lead_analyst_id == lead_analyst_id)
    if q:
        pattern = f"%{escape_like(q)}%"
        stmt = stmt.where(
            or_(
                Incident.title.ilike(pattern, escape="\\"),
                Incident.description.ilike(pattern, escape="\\"),
                Incident.reference.ilike(pattern, escape="\\"),
            )
        )

    total = int(db.scalar(select(func.count()).select_from(stmt.subquery())) or 0)
    items = list(
        db.scalars(
            stmt.order_by(Incident.created_at.desc(), Incident.id.desc())
            .limit(limit)
            .offset(offset)
        )
    )
    return items, total


def create_incident(
    db: Session,
    *,
    title: str,
    description: str,
    severity: Severity,
    lead_analyst_id: uuid.UUID | None,
    alert_ids: Sequence[uuid.UUID],
    recommended_actions: list[str] | None,
    actor: User,
    client_ip: str | None = None,
) -> Incident:
    if lead_analyst_id is not None and db.get(User, lead_analyst_id) is None:
        raise NotFoundError("Lead analyst user not found")

    actions: list[str] = list(recommended_actions or [])
    incident = Incident(
        title=title,
        description=description,
        severity=severity.value,
        status=IncidentStatus.OPEN.value,
        lead_analyst_id=lead_analyst_id or actor.id,
        created_by=actor.id,
        recommended_actions=actions,
    )
    db.add(incident)
    db.flush()

    db.add(
        IncidentTimelineEntry(
            incident_id=incident.id,
            entry_type=TimelineEntryType.CREATED.value,
            summary=f"Incident {incident.reference} opened by {actor.display_name} ({severity.value} severity)",
            details={"severity": severity.value},
            actor_id=actor.id,
        )
    )

    if alert_ids:
        attach_alerts_to_incident(
            db, incident=incident, alert_ids=alert_ids, actor=actor, client_ip=client_ip
        )

    record_audit(
        db,
        action="incident.created",
        actor_id=actor.id,
        target_type="incident",
        target_id=incident.id,
        changes={"reference": incident.reference, "alert_count": len(alert_ids)},
        client_ip=client_ip,
    )
    db.flush()
    return get_incident_or_404(db, incident.id)


def attach_alerts_to_incident(
    db: Session,
    *,
    incident: Incident,
    alert_ids: Sequence[uuid.UUID],
    actor: User,
    client_ip: str | None = None,
) -> Incident:
    unique_ids = list(dict.fromkeys(alert_ids))
    for aid in unique_ids:
        alert = db.get(Alert, aid)
        if alert is None:
            raise NotFoundError(f"Alert {aid} not found")
        existing_link = db.scalar(select(IncidentAlert).where(IncidentAlert.alert_id == aid))
        if existing_link is not None:
            if existing_link.incident_id == incident.id:
                continue
            raise ConflictError(f"Alert {alert.reference} is already attached to another incident")

        db.add(
            IncidentAlert(
                incident_id=incident.id,
                alert_id=alert.id,
                added_by=actor.id,
            )
        )
        if alert.status == AlertStatus.NEW.value:
            alert.status = AlertStatus.INVESTIGATING.value
        if alert.assigned_to is None:
            alert.assigned_to = incident.lead_analyst_id or actor.id

        # Merge rule remediation steps into incident recommended_actions if not present
        rule = db.get(DetectionRule, alert.rule_id)
        if rule and rule.remediation_steps:
            merged = list(incident.recommended_actions or [])
            for step in rule.remediation_steps:
                if step not in merged:
                    merged.append(step)
            incident.recommended_actions = merged

        db.add(
            IncidentTimelineEntry(
                incident_id=incident.id,
                entry_type=TimelineEntryType.ALERT_ADDED.value,
                summary=f"Linked alert {alert.reference}: {alert.title}",
                details={"alert_id": str(alert.id), "reference": alert.reference},
                actor_id=actor.id,
            )
        )

    record_audit(
        db,
        action="incident.alerts_attached",
        actor_id=actor.id,
        target_type="incident",
        target_id=incident.id,
        changes={"alert_ids": [str(a) for a in unique_ids]},
        client_ip=client_ip,
    )
    db.flush()
    return get_incident_or_404(db, incident.id)


def detach_alert_from_incident(
    db: Session,
    *,
    incident: Incident,
    alert_id: uuid.UUID,
    actor: User,
    client_ip: str | None = None,
) -> Incident:
    link = db.scalar(
        select(IncidentAlert).where(
            IncidentAlert.incident_id == incident.id,
            IncidentAlert.alert_id == alert_id,
        )
    )
    if link is None:
        raise NotFoundError("Alert is not attached to this incident")

    alert = db.get(Alert, alert_id)
    ref = alert.reference if alert else str(alert_id)
    db.execute(
        delete(IncidentAlert).where(
            IncidentAlert.incident_id == incident.id,
            IncidentAlert.alert_id == alert_id,
        )
    )
    db.add(
        IncidentTimelineEntry(
            incident_id=incident.id,
            entry_type=TimelineEntryType.ALERT_REMOVED.value,
            summary=f"Detached alert {ref}",
            details={"alert_id": str(alert_id)},
            actor_id=actor.id,
        )
    )
    record_audit(
        db,
        action="incident.alert_detached",
        actor_id=actor.id,
        target_type="incident",
        target_id=incident.id,
        changes={"alert_id": str(alert_id)},
        client_ip=client_ip,
    )
    db.flush()
    return get_incident_or_404(db, incident.id)


def update_incident(
    db: Session,
    incident: Incident,
    *,
    title: str | None = None,
    description: str | None = None,
    new_status: IncidentStatus | None = None,
    new_severity: Severity | None = None,
    lead_analyst_id: uuid.UUID | None = None,
    lead_specified: bool = False,
    findings: str | None = None,
    resolution_summary: str | None = None,
    recommended_actions: list[str] | None = None,
    actor: User,
    client_ip: str | None = None,
) -> Incident:
    changes: dict[str, object] = {}

    if new_status is not None and new_status.value != incident.status:
        current = IncidentStatus(incident.status)
        allowed = ALLOWED_INCIDENT_TRANSITIONS.get(current, frozenset())
        if new_status not in allowed:
            raise InvalidStateTransitionError(
                f"Cannot transition incident from {current.value!r} to {new_status.value!r}"
            )
        incident.status = new_status.value
        incident.closed_at = datetime.now(UTC) if new_status == IncidentStatus.CLOSED else None
        changes["status"] = {"from": current.value, "to": new_status.value}
        db.add(
            IncidentTimelineEntry(
                incident_id=incident.id,
                entry_type=TimelineEntryType.STATUS_CHANGE.value,
                summary=(
                    f"Incident status changed from {current.value} to {new_status.value} "
                    f"by {actor.display_name}"
                ),
                details={"from": current.value, "to": new_status.value},
                actor_id=actor.id,
            )
        )

    if new_severity is not None and new_severity.value != incident.severity:
        changes["severity"] = {"from": incident.severity, "to": new_severity.value}
        incident.severity = new_severity.value

    if title is not None and title != incident.title:
        changes["title"] = title
        incident.title = title

    if description is not None and description != incident.description:
        changes["description_updated"] = True
        incident.description = description

    if lead_specified:
        if lead_analyst_id is not None and db.get(User, lead_analyst_id) is None:
            raise NotFoundError("Lead analyst user not found")
        changes["lead_analyst_id"] = str(lead_analyst_id) if lead_analyst_id else None
        incident.lead_analyst_id = lead_analyst_id

    if findings is not None and findings != incident.findings:
        changes["findings_updated"] = True
        incident.findings = findings

    if resolution_summary is not None and resolution_summary != incident.resolution_summary:
        changes["resolution_summary_updated"] = True
        incident.resolution_summary = resolution_summary

    if recommended_actions is not None:
        changes["recommended_actions_count"] = len(recommended_actions)
        incident.recommended_actions = recommended_actions

    if changes:
        record_audit(
            db,
            action="incident.updated",
            actor_id=actor.id,
            target_type="incident",
            target_id=incident.id,
            changes=changes,
            client_ip=client_ip,
        )
    db.flush()
    return get_incident_or_404(db, incident.id)


def add_incident_note(
    db: Session,
    *,
    incident: Incident,
    body: str,
    author: User,
    client_ip: str | None = None,
) -> InvestigationNote:
    cleaned = body.strip()
    note = InvestigationNote(incident_id=incident.id, author_id=author.id, body=cleaned)
    db.add(note)
    db.add(
        IncidentTimelineEntry(
            incident_id=incident.id,
            entry_type=TimelineEntryType.NOTE.value,
            summary=f"Note added by {author.display_name}: {cleaned[:140]}",
            details={"author": author.username},
            actor_id=author.id,
        )
    )
    record_audit(
        db,
        action="incident.note_added",
        actor_id=author.id,
        target_type="incident",
        target_id=incident.id,
        changes={"note_length": len(cleaned)},
        client_ip=client_ip,
    )
    db.flush()
    db.refresh(note)
    return note


def list_incident_notes(db: Session, incident_id: uuid.UUID) -> list[InvestigationNote]:
    return list(
        db.scalars(
            select(InvestigationNote)
            .where(InvestigationNote.incident_id == incident_id)
            .options(selectinload(InvestigationNote.author))
            .order_by(InvestigationNote.created_at.asc())
        )
    )


def list_incident_alerts(db: Session, incident_id: uuid.UUID) -> list[Alert]:
    return list(
        db.scalars(
            select(Alert)
            .join(IncidentAlert, IncidentAlert.alert_id == Alert.id)
            .where(IncidentAlert.incident_id == incident_id)
            .options(selectinload(Alert.assignee))
            .order_by(Alert.first_seen.asc())
        )
    )
