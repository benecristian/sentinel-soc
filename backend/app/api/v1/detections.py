"""Detection rules inspection, admin configuration and on-demand detection execution."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, Request
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.api.deps import AdminUser, AnalystUser, ViewerUser, get_client_ip, get_db
from app.core.errors import NotFoundError
from app.detection.engine import run_detection_for_time_range
from app.domain.enums import Severity
from app.models import DetectionRule, RuleTechnique, User
from app.schemas.soc import (
    DetectionRuleRead,
    DetectionRuleUpdateRequest,
    DetectionRunRequest,
    RuleMitreLinkRead,
)
from app.services.audit import record_audit

detections_router = APIRouter(prefix="/detections", tags=["detections"])


def _serialize_rule(rule: DetectionRule) -> DetectionRuleRead:
    links = [
        RuleMitreLinkRead(
            technique_id=link.technique_id,
            technique_name=link.technique.name if link.technique else link.technique_id,
            is_primary=link.is_primary,
        )
        for link in sorted(rule.technique_links, key=lambda x: (not x.is_primary, x.technique_id))
    ]
    return DetectionRuleRead(
        id=rule.id,
        name=rule.name,
        description=rule.description,
        category=rule.category,
        severity=Severity(rule.severity),
        enabled=rule.enabled,
        threshold=rule.threshold,
        time_window_seconds=rule.time_window_seconds,
        parameters=rule.parameters or {},
        investigation_steps=rule.investigation_steps or [],
        remediation_steps=rule.remediation_steps or [],
        version=rule.version,
        updated_at=rule.updated_at,
        mitre_techniques=links,
    )


@detections_router.get("/rules", response_model=list[DetectionRuleRead])
def list_detection_rules(
    db: Session = Depends(get_db),
    _: User = ViewerUser,
) -> list[DetectionRuleRead]:
    rows = list(
        db.scalars(
            select(DetectionRule)
            .options(
                selectinload(DetectionRule.technique_links).selectinload(RuleTechnique.technique)
            )
            .order_by(DetectionRule.id)
        )
    )
    return [_serialize_rule(r) for r in rows]


@detections_router.get("/rules/{rule_id}", response_model=DetectionRuleRead)
def get_detection_rule(
    rule_id: str,
    db: Session = Depends(get_db),
    _: User = ViewerUser,
) -> DetectionRuleRead:
    rule = db.scalar(
        select(DetectionRule)
        .where(DetectionRule.id == rule_id)
        .options(selectinload(DetectionRule.technique_links).selectinload(RuleTechnique.technique))
    )
    if rule is None:
        raise NotFoundError(f"Detection rule {rule_id!r} not found")
    return _serialize_rule(rule)


@detections_router.patch("/rules/{rule_id}", response_model=DetectionRuleRead)
def update_detection_rule(
    rule_id: str,
    body: DetectionRuleUpdateRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: User = AdminUser,
) -> DetectionRuleRead:
    rule = db.scalar(
        select(DetectionRule)
        .where(DetectionRule.id == rule_id)
        .options(selectinload(DetectionRule.technique_links).selectinload(RuleTechnique.technique))
    )
    if rule is None:
        raise NotFoundError(f"Detection rule {rule_id!r} not found")

    changes: dict[str, Any] = {}
    if body.enabled is not None and body.enabled != rule.enabled:
        changes["enabled"] = {"from": rule.enabled, "to": body.enabled}
        rule.enabled = body.enabled

    if body.severity is not None and body.severity.value != rule.severity:
        changes["severity"] = {"from": rule.severity, "to": body.severity.value}
        rule.severity = body.severity.value

    if body.threshold is not None and body.threshold != rule.threshold:
        changes["threshold"] = {"from": rule.threshold, "to": body.threshold}
        rule.threshold = body.threshold

    if (
        body.time_window_seconds is not None
        and body.time_window_seconds != rule.time_window_seconds
    ):
        changes["time_window_seconds"] = {
            "from": rule.time_window_seconds,
            "to": body.time_window_seconds,
        }
        rule.time_window_seconds = body.time_window_seconds

    if body.parameters is not None:
        merged = {**(rule.parameters or {}), **body.parameters}
        changes["parameters_updated"] = list(body.parameters.keys())
        rule.parameters = merged

    if changes:
        rule.version += 1
        rule.updated_by = user.id
        record_audit(
            db,
            action="detection_rule.updated",
            actor_id=user.id,
            target_type="detection_rule",
            target_id=rule.id,
            changes=changes,
            client_ip=get_client_ip(request),
        )
        db.commit()
        db.refresh(rule)

    return _serialize_rule(rule)


@detections_router.post("/run")
def run_detections_endpoint(
    body: DetectionRunRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: User = AnalystUser,
) -> dict[str, int]:
    now = datetime.now(UTC)
    start = now - timedelta(hours=body.hours)
    summary = run_detection_for_time_range(db, start_time=start, end_time=now)
    record_audit(
        db,
        action="detections.manual_run",
        actor_id=user.id,
        changes={
            "hours": body.hours,
            "alerts_created": summary.alerts_created,
            "alerts_updated": summary.alerts_updated,
        },
        client_ip=get_client_ip(request),
    )
    db.commit()
    return {
        "rules_evaluated": summary.rules_evaluated,
        "findings_count": summary.findings_count,
        "alerts_created": summary.alerts_created,
        "alerts_updated": summary.alerts_updated,
    }
