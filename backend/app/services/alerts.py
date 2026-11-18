"""Alert triage, lifecycle transitions, investigation notes and queries."""

from __future__ import annotations

import ipaddress
import uuid
from datetime import UTC, datetime

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session, selectinload

from app.core.errors import (
    InvalidStateTransitionError,
    NotFoundError,
    ValidationFailedError,
)
from app.domain.enums import AlertStatus, Severity
from app.hunting.queries import escape_like
from app.models import (
    Alert,
    IncidentAlert,
    InvestigationNote,
    SecurityEvent,
    User,
    alert_events,
)
from app.services.audit import record_audit

ALLOWED_ALERT_TRANSITIONS: dict[AlertStatus, frozenset[AlertStatus]] = {
    AlertStatus.NEW: frozenset(
        {AlertStatus.INVESTIGATING, AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE}
    ),
    AlertStatus.INVESTIGATING: frozenset({AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE}),
    AlertStatus.RESOLVED: frozenset({AlertStatus.INVESTIGATING}),
    AlertStatus.FALSE_POSITIVE: frozenset({AlertStatus.INVESTIGATING}),
}

CLOSING_STATUSES: frozenset[AlertStatus] = frozenset(
    {AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE}
)


def get_alert_or_404(db: Session, alert_id: uuid.UUID) -> Alert:
    alert = db.scalar(
        select(Alert)
        .where(Alert.id == alert_id)
        .options(
            selectinload(Alert.assignee),
            selectinload(Alert.mitre_technique),
            selectinload(Alert.rule),
        )
    )
    if alert is None:
        raise NotFoundError("Alert not found")
    return alert


def list_alerts_page(
    db: Session,
    *,
    status: AlertStatus | None = None,
    severity: Severity | None = None,
    rule_id: str | None = None,
    source_ip: str | None = None,
    username: str | None = None,
    assigned_to: uuid.UUID | None = None,
    q: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[Alert], int]:
    stmt = select(Alert).options(selectinload(Alert.assignee))

    if status is not None:
        stmt = stmt.where(Alert.status == status.value)
    if severity is not None:
        stmt = stmt.where(Alert.severity == severity.value)
    if rule_id:
        stmt = stmt.where(Alert.rule_id == rule_id)
    if source_ip:
        try:
            canon = str(ipaddress.ip_address(source_ip.strip()))
        except ValueError as exc:
            raise ValidationFailedError(f"Invalid source_ip filter: {source_ip!r}") from exc
        stmt = stmt.where(Alert.source_ip == canon)
    if username:
        stmt = stmt.where(Alert.username.ilike(f"%{escape_like(username)}%", escape="\\"))
    if assigned_to is not None:
        stmt = stmt.where(Alert.assigned_to == assigned_to)
    if q:
        pattern = f"%{escape_like(q)}%"
        stmt = stmt.where(
            or_(
                Alert.title.ilike(pattern, escape="\\"),
                Alert.description.ilike(pattern, escape="\\"),
                Alert.reference.ilike(pattern, escape="\\"),
                Alert.rule_name.ilike(pattern, escape="\\"),
            )
        )

    total = int(db.scalar(select(func.count()).select_from(stmt.subquery())) or 0)
    items = list(
        db.scalars(
            stmt.order_by(Alert.created_at.desc(), Alert.id.desc()).limit(limit).offset(offset)
        )
    )
    return items, total


def update_alert(
    db: Session,
    alert: Alert,
    *,
    new_status: AlertStatus | None,
    assigned_to: uuid.UUID | None,
    assign_specified: bool,
    note_body: str | None,
    actor: User,
    client_ip: str | None = None,
) -> Alert:
    changes: dict[str, object] = {}

    if note_body:
        add_alert_note(db, alert=alert, body=note_body, author=actor, client_ip=client_ip)

    if new_status is not None and new_status.value != alert.status:
        current_status = AlertStatus(alert.status)
        allowed = ALLOWED_ALERT_TRANSITIONS.get(current_status, frozenset())
        if new_status not in allowed:
            raise InvalidStateTransitionError(
                f"Cannot transition alert from {current_status.value!r} to {new_status.value!r}"
            )

        if new_status in CLOSING_STATUSES:
            note_count = int(
                db.scalar(
                    select(func.count())
                    .select_from(InvestigationNote)
                    .where(InvestigationNote.alert_id == alert.id)
                )
                or 0
            )
            if note_count == 0:
                raise ValidationFailedError(
                    "Closing an alert as resolved or false_positive requires an investigation note"
                )
            alert.resolved_at = datetime.now(UTC)
        else:
            alert.resolved_at = None

        changes["status"] = {"from": current_status.value, "to": new_status.value}
        alert.status = new_status.value

    if assign_specified:
        if assigned_to is not None and db.get(User, assigned_to) is None:
            raise NotFoundError("Assigned user not found")
        changes["assigned_to"] = {
            "from": str(alert.assigned_to) if alert.assigned_to else None,
            "to": str(assigned_to) if assigned_to else None,
        }
        alert.assigned_to = assigned_to

    if changes:
        record_audit(
            db,
            action="alert.updated",
            actor_id=actor.id,
            target_type="alert",
            target_id=alert.id,
            changes=changes,
            client_ip=client_ip,
        )
    db.flush()
    return get_alert_or_404(db, alert.id)


def add_alert_note(
    db: Session,
    *,
    alert: Alert,
    body: str,
    author: User,
    client_ip: str | None = None,
) -> InvestigationNote:
    note = InvestigationNote(alert_id=alert.id, author_id=author.id, body=body.strip())
    db.add(note)
    record_audit(
        db,
        action="alert.note_added",
        actor_id=author.id,
        target_type="alert",
        target_id=alert.id,
        changes={"note_length": len(note.body)},
        client_ip=client_ip,
    )
    db.flush()
    db.refresh(note)
    return note


def list_alert_notes(db: Session, alert_id: uuid.UUID) -> list[InvestigationNote]:
    return list(
        db.scalars(
            select(InvestigationNote)
            .where(InvestigationNote.alert_id == alert_id)
            .options(selectinload(InvestigationNote.author))
            .order_by(InvestigationNote.created_at.asc())
        )
    )


def get_alert_incident_id(db: Session, alert_id: uuid.UUID) -> uuid.UUID | None:
    return db.scalar(select(IncidentAlert.incident_id).where(IncidentAlert.alert_id == alert_id))


def list_alert_events(
    db: Session, alert_id: uuid.UUID, *, limit: int = 100, offset: int = 0
) -> tuple[list[SecurityEvent], int]:
    stmt = (
        select(SecurityEvent)
        .join(alert_events, alert_events.c.event_id == SecurityEvent.id)
        .where(alert_events.c.alert_id == alert_id)
    )
    total = int(db.scalar(select(func.count()).select_from(stmt.subquery())) or 0)
    items = list(
        db.scalars(stmt.order_by(SecurityEvent.timestamp.asc()).limit(limit).offset(offset))
    )
    return items, total
