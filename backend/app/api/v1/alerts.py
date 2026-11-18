"""Alert management endpoints."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy.orm import Session

from app.api.deps import AnalystUser, ViewerUser, get_client_ip, get_db
from app.domain.enums import AlertStatus, Severity
from app.models import Alert, User
from app.schemas.common import MAX_PAGE_SIZE, Page
from app.schemas.soc import (
    AlertDetailRead,
    AlertSummaryRead,
    AlertUpdateRequest,
    InvestigationNoteRead,
    NoteCreateRequest,
    SecurityEventRead,
)
from app.services.alerts import (
    add_alert_note,
    get_alert_incident_id,
    get_alert_or_404,
    list_alert_events,
    list_alert_notes,
    list_alerts_page,
    update_alert,
)

alerts_router = APIRouter(prefix="/alerts", tags=["alerts"])


def _build_alert_detail(db: Session, alert: Alert) -> AlertDetailRead:
    notes = list_alert_notes(db, alert.id)
    incident_id = get_alert_incident_id(db, alert.id)
    inv_steps = list(alert.rule.investigation_steps) if alert.rule else []
    rem_steps = list(alert.rule.remediation_steps) if alert.rule else []
    summary = AlertSummaryRead.model_validate(alert)
    return AlertDetailRead(
        **summary.model_dump(),
        description=alert.description,
        evidence=alert.evidence or {},
        incident_id=incident_id,
        investigation_steps=inv_steps,
        remediation_steps=rem_steps,
        notes=[InvestigationNoteRead.model_validate(n) for n in notes],
    )


@alerts_router.get("", response_model=Page[AlertSummaryRead])
def list_alerts(
    db: Session = Depends(get_db),
    _: User = ViewerUser,
    status_filter: AlertStatus | None = Query(default=None, alias="status"),
    severity: Severity | None = Query(default=None),
    rule_id: str | None = Query(default=None),
    source_ip: str | None = Query(default=None, alias="ip"),
    username: str | None = Query(default=None),
    assigned_to: uuid.UUID | None = Query(default=None),
    q: str | None = Query(default=None, max_length=256),
    limit: int = Query(default=50, ge=1, le=MAX_PAGE_SIZE),
    offset: int = Query(default=0, ge=0, le=1_000_000),
) -> Page[AlertSummaryRead]:
    items, total = list_alerts_page(
        db,
        status=status_filter,
        severity=severity,
        rule_id=rule_id,
        source_ip=source_ip,
        username=username,
        assigned_to=assigned_to,
        q=q,
        limit=limit,
        offset=offset,
    )
    return Page(
        items=[AlertSummaryRead.model_validate(a) for a in items],
        total=total,
        limit=limit,
        offset=offset,
    )


@alerts_router.get("/{alert_id}", response_model=AlertDetailRead)
def get_alert(
    alert_id: uuid.UUID,
    db: Session = Depends(get_db),
    _: User = ViewerUser,
) -> AlertDetailRead:
    alert = get_alert_or_404(db, alert_id)
    return _build_alert_detail(db, alert)


@alerts_router.patch("/{alert_id}", response_model=AlertDetailRead)
def patch_alert(
    alert_id: uuid.UUID,
    body: AlertUpdateRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: User = AnalystUser,
) -> AlertDetailRead:
    alert = get_alert_or_404(db, alert_id)
    updated = update_alert(
        db,
        alert,
        new_status=body.status,
        assigned_to=body.assigned_to,
        assign_specified="assigned_to" in body.model_fields_set,
        note_body=body.note,
        actor=user,
        client_ip=get_client_ip(request),
    )
    db.commit()
    return _build_alert_detail(db, updated)


@alerts_router.get("/{alert_id}/events", response_model=Page[SecurityEventRead])
def get_alert_related_events(
    alert_id: uuid.UUID,
    db: Session = Depends(get_db),
    _: User = ViewerUser,
    limit: int = Query(default=100, ge=1, le=MAX_PAGE_SIZE),
    offset: int = Query(default=0, ge=0, le=1_000_000),
) -> Page[SecurityEventRead]:
    get_alert_or_404(db, alert_id)
    events, total = list_alert_events(db, alert_id, limit=limit, offset=offset)
    return Page(
        items=[SecurityEventRead.model_validate(e) for e in events],
        total=total,
        limit=limit,
        offset=offset,
    )


@alerts_router.post(
    "/{alert_id}/notes",
    response_model=InvestigationNoteRead,
    status_code=status.HTTP_201_CREATED,
)
def create_alert_note(
    alert_id: uuid.UUID,
    body: NoteCreateRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: User = AnalystUser,
) -> InvestigationNoteRead:
    alert = get_alert_or_404(db, alert_id)
    note = add_alert_note(
        db,
        alert=alert,
        body=body.body,
        author=user,
        client_ip=get_client_ip(request),
    )
    db.commit()
    return InvestigationNoteRead.model_validate(note)
