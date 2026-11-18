"""Dashboard overview telemetry aggregation."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from app.domain.enums import AlertStatus, IncidentStatus, Severity
from app.models import Alert, DetectionRule, Incident, SecurityEvent


def build_dashboard_overview(db: Session, hours: int = 24) -> dict[str, Any]:
    now = datetime.now(UTC)
    since = now - timedelta(hours=hours)

    total_events = int(db.scalar(select(func.count(SecurityEvent.id))) or 0)
    events_in_window = int(
        db.scalar(select(func.count(SecurityEvent.id)).where(SecurityEvent.timestamp >= since)) or 0
    )
    synthetic_events = int(
        db.scalar(select(func.count(SecurityEvent.id)).where(SecurityEvent.is_synthetic.is_(True)))
        or 0
    )

    total_alerts = int(db.scalar(select(func.count(Alert.id))) or 0)
    open_alerts = int(
        db.scalar(
            select(func.count(Alert.id)).where(
                Alert.status.in_((AlertStatus.NEW.value, AlertStatus.INVESTIGATING.value))
            )
        )
        or 0
    )
    critical_open_alerts = int(
        db.scalar(
            select(func.count(Alert.id)).where(
                Alert.status.in_((AlertStatus.NEW.value, AlertStatus.INVESTIGATING.value)),
                Alert.severity.in_((Severity.CRITICAL.value, Severity.HIGH.value)),
            )
        )
        or 0
    )
    open_incidents = int(
        db.scalar(
            select(func.count(Incident.id)).where(Incident.status != IncidentStatus.CLOSED.value)
        )
        or 0
    )
    enabled_rules = int(
        db.scalar(select(func.count(DetectionRule.id)).where(DetectionRule.enabled.is_(True))) or 0
    )

    # Hourly event & alert timeline (up to 24 buckets across the requested window)
    bucket_hours = max(1, hours // 24)
    event_buckets: dict[datetime, int] = {
        row[0]: int(row[1])
        for row in db.execute(
            select(
                func.date_trunc("hour", SecurityEvent.timestamp).label("bucket"),
                func.count(SecurityEvent.id),
            )
            .where(SecurityEvent.timestamp >= since)
            .group_by("bucket")
        ).all()
    }
    alert_buckets: dict[datetime, int] = {
        row[0]: int(row[1])
        for row in db.execute(
            select(
                func.date_trunc("hour", Alert.last_seen).label("bucket"),
                func.count(Alert.id),
            )
            .where(Alert.last_seen >= since)
            .group_by("bucket")
        ).all()
    }

    current_hour = now.replace(minute=0, second=0, microsecond=0)
    timeline: list[dict[str, Any]] = []
    for step in range(min(hours, 24) - 1, -1, -1):
        bucket_ts = current_hour - timedelta(hours=step * bucket_hours)
        timeline.append(
            {
                "hour": bucket_ts.isoformat(),
                "label": bucket_ts.strftime("%H:%M"),
                "events": int(event_buckets.get(bucket_ts, 0)),
                "alerts": int(alert_buckets.get(bucket_ts, 0)),
            }
        )

    # Alert severity distribution
    sev_rows = dict(
        db.execute(select(Alert.severity, func.count(Alert.id)).group_by(Alert.severity)).all()
    )
    severity_distribution = [
        {"severity": sev.value, "count": int(sev_rows.get(sev.value, 0))}
        for sev in (
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
            Severity.INFORMATIONAL,
        )
    ]

    # Event type distribution
    type_rows = db.execute(
        select(SecurityEvent.event_type, func.count(SecurityEvent.id))
        .group_by(SecurityEvent.event_type)
        .order_by(desc(func.count(SecurityEvent.id)))
    ).all()
    event_type_distribution = [{"event_type": str(r[0]), "count": int(r[1])} for r in type_rows]

    # Top source IPs
    ip_rows = db.execute(
        select(
            SecurityEvent.source_ip,
            func.count(SecurityEvent.id).label("event_count"),
            func.count().filter(SecurityEvent.event_outcome == "failure").label("failure_count"),
        )
        .where(SecurityEvent.source_ip.is_not(None))
        .group_by(SecurityEvent.source_ip)
        .order_by(desc("event_count"))
        .limit(8)
    ).all()
    top_source_ips = [
        {
            "source_ip": str(r.source_ip),
            "event_count": int(r.event_count),
            "failure_count": int(r.failure_count),
        }
        for r in ip_rows
    ]

    # Recent alerts
    recent_alerts = list(db.scalars(select(Alert).order_by(Alert.created_at.desc()).limit(8)))

    return {
        "kpis": {
            "total_events": total_events,
            "events_in_window": events_in_window,
            "events_per_hour": round(events_in_window / max(1, hours), 1),
            "synthetic_events": synthetic_events,
            "total_alerts": total_alerts,
            "open_alerts": open_alerts,
            "critical_or_high_open_alerts": critical_open_alerts,
            "open_incidents": open_incidents,
            "enabled_rules": enabled_rules,
        },
        "timeline": timeline,
        "severity_distribution": severity_distribution,
        "event_type_distribution": event_type_distribution,
        "top_source_ips": top_source_ips,
        "recent_alerts": [
            {
                "id": str(a.id),
                "reference": a.reference,
                "rule_id": a.rule_id,
                "rule_name": a.rule_name,
                "severity": a.severity,
                "status": a.status,
                "title": a.title,
                "source_ip": str(a.source_ip) if a.source_ip else None,
                "username": a.username,
                "mitre_technique_id": a.mitre_technique_id,
                "event_count": a.event_count,
                "created_at": a.created_at.isoformat(),
                "last_seen": a.last_seen.isoformat(),
            }
            for a in recent_alerts
        ],
    }
