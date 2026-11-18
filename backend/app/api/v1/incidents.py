"""Incident management endpoints."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy.orm import Session

from app.api.deps import AnalystUser, ViewerUser, get_client_ip, get_db
from app.domain.enums import IncidentStatus, Severity
from app.models import Incident, User
from app.schemas.auth import UserSummary
from app.schemas.common import MAX_PAGE_SIZE, Page
from app.schemas.soc import (
    AlertSummaryRead,
    IncidentAttachAlertsRequest,
    IncidentCreateRequest,
    IncidentDetailRead,
    IncidentSummaryRead,
    IncidentUpdateRequest,
    InvestigationNoteRead,
    NoteCreateRequest,
    TimelineEntryRead,
)
from app.services.incidents import (
    add_incident_note,
    attach_alerts_to_incident,
    create_incident,
    detach_alert_from_incident,
    get_incident_or_404,
    list_incident_alerts,
    list_incident_notes,
    list_incidents_page,
    update_incident,
)

incidents_router = APIRouter(prefix="/incidents", tags=["incidents"])


def _to_summary(inc: Incident) -> IncidentSummaryRead:
    return IncidentSummaryRead(
        id=inc.id,
        reference=inc.reference,
        title=inc.title,
        description=inc.description,
        severity=Severity(inc.severity),
        status=IncidentStatus(inc.status),
        lead_analyst_id=inc.lead_analyst_id,
        lead_analyst=UserSummary.model_validate(inc.lead_analyst) if inc.lead_analyst else None,
        alert_count=len(inc.alert_links),
        created_at=inc.created_at,
        updated_at=inc.updated_at,
        closed_at=inc.closed_at,
    )


def _to_detail(db: Session, inc: Incident) -> IncidentDetailRead:
    alerts = list_incident_alerts(db, inc.id)
    notes = list_incident_notes(db, inc.id)
    summary = _to_summary(inc)
    return IncidentDetailRead(
        **summary.model_dump(),
        recommended_actions=list(inc.recommended_actions or []),
        findings=inc.findings,
        resolution_summary=inc.resolution_summary,
        alerts=[AlertSummaryRead.model_validate(a) for a in alerts],
        timeline=[TimelineEntryRead.model_validate(t) for t in inc.timeline],
        notes=[InvestigationNoteRead.model_validate(n) for n in notes],
    )


@incidents_router.get("", response_model=Page[IncidentSummaryRead])
def list_incidents(
    db: Session = Depends(get_db),
    _: User = ViewerUser,
    status_filter: IncidentStatus | None = Query(default=None, alias="status"),
    severity: Severity | None = Query(default=None),
    lead_analyst_id: uuid.UUID | None = Query(default=None, alias="lead"),
    q: str | None = Query(default=None, max_length=256),
    limit: int = Query(default=50, ge=1, le=MAX_PAGE_SIZE),
    offset: int = Query(default=0, ge=0, le=1_000_000),
) -> Page[IncidentSummaryRead]:
    items, total = list_incidents_page(
        db,
        status=status_filter,
        severity=severity,
        lead_analyst_id=lead_analyst_id,
        q=q,
        limit=limit,
        offset=offset,
    )
    return Page(
        items=[_to_summary(inc) for inc in items],
        total=total,
        limit=limit,
        offset=offset,
    )


@incidents_router.post("", response_model=IncidentDetailRead, status_code=status.HTTP_201_CREATED)
def create_incident_endpoint(
    body: IncidentCreateRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: User = AnalystUser,
) -> IncidentDetailRead:
    incident = create_incident(
        db,
        title=body.title,
        description=body.description,
        severity=body.severity,
        lead_analyst_id=body.lead_analyst_id,
        alert_ids=body.alert_ids,
        recommended_actions=body.recommended_actions,
        actor=user,
        client_ip=get_client_ip(request),
    )
    db.commit()
    return _to_detail(db, incident)


@incidents_router.get("/{incident_id}", response_model=IncidentDetailRead)
def get_incident(
    incident_id: uuid.UUID,
    db: Session = Depends(get_db),
    _: User = ViewerUser,
) -> IncidentDetailRead:
    incident = get_incident_or_404(db, incident_id)
    return _to_detail(db, incident)


@incidents_router.patch("/{incident_id}", response_model=IncidentDetailRead)
def patch_incident(
    incident_id: uuid.UUID,
    body: IncidentUpdateRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: User = AnalystUser,
) -> IncidentDetailRead:
    incident = get_incident_or_404(db, incident_id)
    updated = update_incident(
        db,
        incident,
        title=body.title,
        description=body.description,
        new_status=body.status,
        new_severity=body.severity,
        lead_analyst_id=body.lead_analyst_id,
        lead_specified="lead_analyst_id" in body.model_fields_set,
        findings=body.findings,
        resolution_summary=body.resolution_summary,
        recommended_actions=body.recommended_actions,
        actor=user,
        client_ip=get_client_ip(request),
    )
    db.commit()
    return _to_detail(db, updated)


@incidents_router.post("/{incident_id}/alerts", response_model=IncidentDetailRead)
def attach_alerts_endpoint(
    incident_id: uuid.UUID,
    body: IncidentAttachAlertsRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: User = AnalystUser,
) -> IncidentDetailRead:
    incident = get_incident_or_404(db, incident_id)
    updated = attach_alerts_to_incident(
        db,
        incident=incident,
        alert_ids=body.alert_ids,
        actor=user,
        client_ip=get_client_ip(request),
    )
    db.commit()
    return _to_detail(db, updated)


@incidents_router.delete("/{incident_id}/alerts/{alert_id}", response_model=IncidentDetailRead)
def detach_alert_endpoint(
    incident_id: uuid.UUID,
    alert_id: uuid.UUID,
    request: Request,
    db: Session = Depends(get_db),
    user: User = AnalystUser,
) -> IncidentDetailRead:
    incident = get_incident_or_404(db, incident_id)
    updated = detach_alert_from_incident(
        db,
        incident=incident,
        alert_id=alert_id,
        actor=user,
        client_ip=get_client_ip(request),
    )
    db.commit()
    return _to_detail(db, updated)


@incidents_router.post(
    "/{incident_id}/notes",
    response_model=InvestigationNoteRead,
    status_code=status.HTTP_201_CREATED,
)
def create_incident_note(
    incident_id: uuid.UUID,
    body: NoteCreateRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: User = AnalystUser,
) -> InvestigationNoteRead:
    incident = get_incident_or_404(db, incident_id)
    note = add_incident_note(
        db,
        incident=incident,
        body=body.body,
        author=user,
        client_ip=get_client_ip(request),
    )
    db.commit()
    return InvestigationNoteRead.model_validate(note)
