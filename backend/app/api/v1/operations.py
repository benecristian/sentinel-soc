"""Dashboard, MITRE ATT&CK, Threat Hunting, Simulation Center, Reports and System Info endpoints."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, Query, Request, Response, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import __version__
from app.api.deps import (
    AnalystUser,
    ViewerUser,
    get_client_ip,
    get_db,
    get_settings_dep,
    rate_limit,
)
from app.core.config import Settings
from app.domain.enums import EventOutcome, EventType, Severity
from app.hunting.queries import (
    ALLOWED_JSON_FIELDS,
    HUNT_CATALOG,
    EventFilterParams,
    execute_predefined_hunt,
    pivot_on_ip,
    pivot_on_user,
    query_events_page,
)
from app.ingestion.parsers import SUPPORTED_FORMATS
from app.mitre.catalog import (
    CoverageStatus,
    compute_mitre_coverage_matrix,
    compute_mitre_techniques,
)
from app.models import (
    Alert,
    DetectionRule,
    Incident,
    SecurityEvent,
    SimulationRun,
    User,
)
from app.reporting.reports import build_incident_report_data, render_incident_pdf
from app.schemas.common import MAX_PAGE_SIZE, Page
from app.schemas.soc import (
    ScenarioRead,
    SecurityEventRead,
    SimulationRunRead,
    SimulationRunRequest,
)
from app.services.audit import record_audit
from app.services.dashboard import build_dashboard_overview
from app.simulation.runner import execute_simulation_scenario
from app.simulation.scenarios import SCENARIOS

dashboard_router = APIRouter(prefix="/dashboard", tags=["dashboard"])
mitre_router = APIRouter(prefix="/mitre", tags=["mitre"])
hunting_router = APIRouter(prefix="/hunting", tags=["hunting"])
simulations_router = APIRouter(prefix="/simulations", tags=["simulations"])
reports_router = APIRouter(prefix="/reports", tags=["reports"])
system_router = APIRouter(prefix="/system", tags=["system"])


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------


@dashboard_router.get("/overview")
def get_dashboard_overview(
    hours: int = Query(default=24, ge=1, le=720),
    db: Session = Depends(get_db),
    _: User = ViewerUser,
) -> dict[str, Any]:
    return build_dashboard_overview(db, hours=hours)


# ---------------------------------------------------------------------------
# MITRE ATT&CK
# ---------------------------------------------------------------------------


@mitre_router.get("/techniques")
def list_mitre_techniques(
    tactic: str | None = Query(default=None),
    coverage: CoverageStatus | None = Query(default=None),
    db: Session = Depends(get_db),
    _: User = ViewerUser,
) -> list[dict[str, Any]]:
    return compute_mitre_techniques(db, tactic_id=tactic, coverage_filter=coverage)


@mitre_router.get("/coverage")
def get_mitre_coverage(
    db: Session = Depends(get_db),
    _: User = ViewerUser,
) -> dict[str, Any]:
    return compute_mitre_coverage_matrix(db)


# ---------------------------------------------------------------------------
# Threat Hunting
# ---------------------------------------------------------------------------


@hunting_router.get("/search", response_model=Page[SecurityEventRead])
def hunt_events(
    db: Session = Depends(get_db),
    _: User = ViewerUser,
    ip: str | None = Query(default=None),
    source_ip: str | None = Query(default=None),
    destination_ip: str | None = Query(default=None),
    cidr: str | None = Query(default=None),
    username: str | None = Query(default=None),
    hostname: str | None = Query(default=None),
    event_type: EventType | None = Query(default=None),
    event_outcome: EventOutcome | None = Query(default=None),
    severity: Severity | None = Query(default=None),
    start_time: datetime | None = Query(default=None, alias="from"),
    end_time: datetime | None = Query(default=None, alias="to"),
    q: str | None = Query(default=None, max_length=256),
    field_key: str | None = Query(default=None),
    field_value: str | None = Query(default=None, max_length=256),
    limit: int = Query(default=50, ge=1, le=MAX_PAGE_SIZE),
    offset: int = Query(default=0, ge=0, le=1_000_000),
) -> Page[SecurityEventRead]:
    params = EventFilterParams(
        ip=ip,
        source_ip=source_ip,
        destination_ip=destination_ip,
        cidr=cidr,
        username=username,
        hostname=hostname,
        event_type=event_type,
        event_outcome=event_outcome,
        severity=severity,
        start_time=start_time,
        end_time=end_time,
        q=q,
        field_key=field_key,
        field_value=field_value,
    )
    items, total = query_events_page(db, params, limit=limit, offset=offset)
    return Page(
        items=[SecurityEventRead.model_validate(item) for item in items],
        total=total,
        limit=limit,
        offset=offset,
    )


@hunting_router.get("/entities/ip/{ip}")
def get_ip_pivot(
    ip: str,
    db: Session = Depends(get_db),
    _: User = ViewerUser,
) -> dict[str, Any]:
    return pivot_on_ip(db, ip)


@hunting_router.get("/entities/user/{username}")
def get_user_pivot(
    username: str,
    db: Session = Depends(get_db),
    _: User = ViewerUser,
) -> dict[str, Any]:
    return pivot_on_user(db, username)


@hunting_router.get("/queries")
def list_predefined_hunts(_: User = ViewerUser) -> dict[str, Any]:
    return {
        "queries": list(HUNT_CATALOG),
        "allowed_json_fields": sorted(ALLOWED_JSON_FIELDS),
    }


@hunting_router.post("/queries/{query_id}/run")
def run_predefined_hunt(
    query_id: str,
    db: Session = Depends(get_db),
    _: User = ViewerUser,
) -> dict[str, Any]:
    return execute_predefined_hunt(db, query_id)


# ---------------------------------------------------------------------------
# Simulation Center
# ---------------------------------------------------------------------------


def _serialize_scenarios() -> list[ScenarioRead]:
    return [
        ScenarioRead(
            id=s.id,
            name=s.name,
            category=s.category,
            description=s.description,
            expected_rules=list(s.expected_rules),
            mitre_techniques=list(s.mitre_techniques),
            default_seed=s.default_seed,
        )
        for s in SCENARIOS
    ]


@simulations_router.get("", response_model=dict[str, Any])
def get_simulations_overview(
    db: Session = Depends(get_db),
    _: User = ViewerUser,
) -> dict[str, Any]:
    runs = list(
        db.scalars(select(SimulationRun).order_by(SimulationRun.started_at.desc()).limit(25))
    )
    return {
        "scenarios": [s.model_dump() for s in _serialize_scenarios()],
        "recent_runs": [SimulationRunRead.model_validate(r).model_dump() for r in runs],
    }


@simulations_router.get("/scenarios", response_model=list[ScenarioRead])
def list_simulation_scenarios(_: User = ViewerUser) -> list[ScenarioRead]:
    return _serialize_scenarios()


@simulations_router.get("/runs", response_model=list[SimulationRunRead])
def list_simulation_runs(
    db: Session = Depends(get_db),
    _: User = ViewerUser,
) -> list[SimulationRunRead]:
    runs = list(
        db.scalars(select(SimulationRun).order_by(SimulationRun.started_at.desc()).limit(50))
    )
    return [SimulationRunRead.model_validate(r) for r in runs]


@simulations_router.post(
    "/{scenario_id}/run",
    response_model=SimulationRunRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(rate_limit("simulation", "simulation_rate_limit_per_minute"))],
)
def run_simulation_endpoint(
    scenario_id: str,
    request: Request,
    body: SimulationRunRequest | None = None,
    db: Session = Depends(get_db),
    user: User = AnalystUser,
) -> SimulationRunRead:
    seed = body.seed if body else None
    sim_run = execute_simulation_scenario(db, scenario_id, seed=seed, triggered_by=user.id)
    record_audit(
        db,
        action="simulation.executed",
        actor_id=user.id,
        target_type="simulation_run",
        target_id=sim_run.id,
        changes={
            "scenario_id": scenario_id,
            "seed": sim_run.seed,
            "events_generated": sim_run.events_generated,
            "alerts_generated": sim_run.alerts_generated,
        },
        client_ip=get_client_ip(request),
    )
    db.commit()
    db.refresh(sim_run)
    return SimulationRunRead.model_validate(sim_run)


# ---------------------------------------------------------------------------
# Incident Reports (JSON & PDF)
# ---------------------------------------------------------------------------


@reports_router.get("/incidents/{incident_id}")
def get_incident_report_json(
    incident_id: uuid.UUID,
    db: Session = Depends(get_db),
    _: User = ViewerUser,
) -> dict[str, Any]:
    return build_incident_report_data(db, incident_id)


@reports_router.get("/incidents/{incident_id}/pdf")
def get_incident_report_pdf(
    incident_id: uuid.UUID,
    db: Session = Depends(get_db),
    _: User = ViewerUser,
) -> Response:
    report_data = build_incident_report_data(db, incident_id)
    pdf_bytes = render_incident_pdf(report_data)
    ref = report_data["incident"]["reference"]
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="sentinel-soc-{ref}.pdf"'},
    )


# ---------------------------------------------------------------------------
# System Info (Settings page)
# ---------------------------------------------------------------------------


@system_router.get("/info")
def get_system_info(
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings_dep),
    _: User = ViewerUser,
) -> dict[str, Any]:
    return {
        "application": settings.app_name,
        "version": __version__,
        "environment": settings.environment,
        "supported_log_formats": list(SUPPORTED_FORMATS),
        "limits": {
            "max_upload_mb": settings.max_upload_mb,
            "max_line_length": settings.max_line_length,
            "max_lines_per_upload": settings.max_lines_per_upload,
            "max_ingest_batch": settings.max_ingest_batch,
            "rate_limit_enabled": settings.rate_limit_enabled,
        },
        "counts": {
            "events": int(db.scalar(select(func.count(SecurityEvent.id))) or 0),
            "alerts": int(db.scalar(select(func.count(Alert.id))) or 0),
            "incidents": int(db.scalar(select(func.count(Incident.id))) or 0),
            "rules": int(db.scalar(select(func.count(DetectionRule.id))) or 0),
            "simulations": int(db.scalar(select(func.count(SimulationRun.id))) or 0),
        },
    }
