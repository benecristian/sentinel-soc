"""Threat hunting service: safe parameterized queries, entity pivots, and predefined hunts.

Security design:
* Every filter value is bound as a SQL parameter; no user string is ever
  interpolated into SQL text.
* CIDR inputs are parsed with `ipaddress.ip_network` before reaching PostgreSQL's
  `<<=` inet containment operator.
* Free-text `ILIKE` queries escape `%`, `_` and `\\` so wildcard characters in
  search strings behave as literals.
* JSON field filters are restricted to `ALLOWED_JSON_FIELDS`.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import Select, String, cast, desc, func, literal, or_, select
from sqlalchemy.dialects.postgresql import INET
from sqlalchemy.orm import Session

from app.core.errors import NotFoundError, ValidationFailedError
from app.domain.enums import EventOutcome, EventType, Severity
from app.models import Alert, SecurityEvent

ALLOWED_JSON_FIELDS: frozenset[str] = frozenset(
    {
        "url.path",
        "url.original",
        "user_agent.original",
        "dns.question.name",
        "dns.question.type",
        "process.command_line",
        "http.request.method",
        "auth.method",
        "firewall.rule_action",
        "user.target.name",
    }
)


def escape_like(term: str) -> str:
    return term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


@dataclass(slots=True)
class EventFilterParams:
    ip: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    cidr: str | None = None
    username: str | None = None
    hostname: str | None = None
    event_type: EventType | None = None
    event_outcome: EventOutcome | None = None
    severity: Severity | None = None
    log_source: str | None = None
    is_synthetic: bool | None = None
    start_time: datetime | None = None
    end_time: datetime | None = None
    q: str | None = None
    field_key: str | None = None
    field_value: str | None = None


def apply_event_filters(
    stmt: Select[SecurityEvent], params: EventFilterParams
) -> Select[SecurityEvent]:
    if params.ip:
        try:
            canon = str(ipaddress.ip_address(params.ip.strip()))
        except ValueError as exc:
            raise ValidationFailedError(f"Invalid IP address filter: {params.ip!r}") from exc
        stmt = stmt.where(
            or_(SecurityEvent.source_ip == canon, SecurityEvent.destination_ip == canon)
        )

    if params.source_ip:
        try:
            canon_src = str(ipaddress.ip_address(params.source_ip.strip()))
        except ValueError as exc:
            raise ValidationFailedError(f"Invalid source_ip filter: {params.source_ip!r}") from exc
        stmt = stmt.where(SecurityEvent.source_ip == canon_src)

    if params.destination_ip:
        try:
            canon_dst = str(ipaddress.ip_address(params.destination_ip.strip()))
        except ValueError as exc:
            raise ValidationFailedError(
                f"Invalid destination_ip filter: {params.destination_ip!r}"
            ) from exc
        stmt = stmt.where(SecurityEvent.destination_ip == canon_dst)

    if params.cidr:
        try:
            net = str(ipaddress.ip_network(params.cidr.strip(), strict=False))
        except ValueError as exc:
            raise ValidationFailedError(f"Invalid CIDR network filter: {params.cidr!r}") from exc
        cidr_param = cast(literal(net), INET)
        stmt = stmt.where(
            or_(
                SecurityEvent.source_ip.op("<<=")(cidr_param),
                SecurityEvent.destination_ip.op("<<=")(cidr_param),
            )
        )

    if params.username:
        stmt = stmt.where(
            SecurityEvent.username.ilike(f"%{escape_like(params.username)}%", escape="\\")
        )

    if params.hostname:
        stmt = stmt.where(
            SecurityEvent.hostname.ilike(f"%{escape_like(params.hostname)}%", escape="\\")
        )

    if params.event_type:
        stmt = stmt.where(SecurityEvent.event_type == params.event_type.value)

    if params.event_outcome:
        stmt = stmt.where(SecurityEvent.event_outcome == params.event_outcome.value)

    if params.severity:
        stmt = stmt.where(SecurityEvent.severity == params.severity.value)

    if params.log_source:
        stmt = stmt.where(SecurityEvent.log_source == params.log_source)

    if params.is_synthetic is not None:
        stmt = stmt.where(SecurityEvent.is_synthetic.is_(params.is_synthetic))

    if params.start_time:
        stmt = stmt.where(SecurityEvent.timestamp >= params.start_time)

    if params.end_time:
        stmt = stmt.where(SecurityEvent.timestamp <= params.end_time)

    if params.field_key:
        if params.field_key not in ALLOWED_JSON_FIELDS:
            raise ValidationFailedError(
                f"Unsupported normalized field {params.field_key!r}. "
                f"Allowed: {', '.join(sorted(ALLOWED_JSON_FIELDS))}"
            )
        if params.field_value:
            pattern = f"%{escape_like(params.field_value)}%"
            stmt = stmt.where(
                cast(SecurityEvent.normalized_event[params.field_key].astext, String).ilike(
                    pattern, escape="\\"
                )
            )

    if params.q:
        pattern = f"%{escape_like(params.q)}%"
        stmt = stmt.where(
            or_(
                SecurityEvent.raw_event.ilike(pattern, escape="\\"),
                SecurityEvent.username.ilike(pattern, escape="\\"),
                SecurityEvent.hostname.ilike(pattern, escape="\\"),
                SecurityEvent.event_action.ilike(pattern, escape="\\"),
            )
        )

    return stmt


def query_events_page(
    db: Session,
    params: EventFilterParams,
    *,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[SecurityEvent], int]:
    base_stmt = apply_event_filters(select(SecurityEvent), params)
    total = int(db.scalar(select(func.count()).select_from(base_stmt.subquery())) or 0)
    ordered_stmt = (
        base_stmt.order_by(SecurityEvent.timestamp.desc(), SecurityEvent.id.desc())
        .limit(limit)
        .offset(offset)
    )
    items: list[SecurityEvent] = list(db.scalars(ordered_stmt).all())
    return items, total


def pivot_on_ip(db: Session, ip_raw: str) -> dict[str, Any]:
    try:
        ip = str(ipaddress.ip_address(ip_raw.strip()))
    except ValueError as exc:
        raise ValidationFailedError(f"Invalid IP address: {ip_raw!r}") from exc

    events = list(
        db.scalars(
            select(SecurityEvent)
            .where(or_(SecurityEvent.source_ip == ip, SecurityEvent.destination_ip == ip))
            .order_by(SecurityEvent.timestamp.desc())
            .limit(500)
        )
    )
    alerts = list(
        db.scalars(
            select(Alert).where(Alert.source_ip == ip).order_by(Alert.created_at.desc()).limit(50)
        )
    )

    by_type: dict[str, int] = {}
    by_outcome: dict[str, int] = {}
    usernames: set[str] = set()
    ports: set[int] = set()
    hostnames: set[str] = set()
    as_source = 0
    as_dest = 0

    for ev in events:
        by_type[ev.event_type] = by_type.get(ev.event_type, 0) + 1
        by_outcome[ev.event_outcome] = by_outcome.get(ev.event_outcome, 0) + 1
        if str(ev.source_ip) == ip:
            as_source += 1
        if str(ev.destination_ip) == ip:
            as_dest += 1
        if ev.username:
            usernames.add(ev.username)
        if ev.destination_port is not None:
            ports.add(ev.destination_port)
        if ev.hostname:
            hostnames.add(ev.hostname)

    return {
        "entity_type": "ip",
        "entity": ip,
        "total_events": len(events),
        "as_source_count": as_source,
        "as_destination_count": as_dest,
        "first_seen": events[-1].timestamp if events else None,
        "last_seen": events[0].timestamp if events else None,
        "event_types": by_type,
        "outcomes": by_outcome,
        "related_usernames": sorted(usernames)[:25],
        "destination_ports": sorted(ports)[:40],
        "hostnames": sorted(hostnames)[:20],
        "related_alerts": [
            {
                "id": str(a.id),
                "reference": a.reference,
                "rule_id": a.rule_id,
                "title": a.title,
                "severity": a.severity,
                "status": a.status,
                "created_at": a.created_at.isoformat(),
            }
            for a in alerts
        ],
    }


def pivot_on_user(db: Session, username: str) -> dict[str, Any]:
    clean = username.strip()
    if not clean or len(clean) > 256:
        raise ValidationFailedError("Invalid username")

    events = list(
        db.scalars(
            select(SecurityEvent)
            .where(SecurityEvent.username == clean)
            .order_by(SecurityEvent.timestamp.desc())
            .limit(500)
        )
    )
    alerts = list(
        db.scalars(
            select(Alert).where(Alert.username == clean).order_by(Alert.created_at.desc()).limit(50)
        )
    )

    by_type: dict[str, int] = {}
    by_outcome: dict[str, int] = {}
    source_ips: set[str] = set()
    hostnames: set[str] = set()
    commands: list[str] = []

    for ev in events:
        by_type[ev.event_type] = by_type.get(ev.event_type, 0) + 1
        by_outcome[ev.event_outcome] = by_outcome.get(ev.event_outcome, 0) + 1
        if ev.source_ip:
            source_ips.add(str(ev.source_ip))
        if ev.hostname:
            hostnames.add(ev.hostname)
        cmd = (ev.normalized_event or {}).get("process.command_line")
        if isinstance(cmd, str) and cmd not in commands and len(commands) < 20:
            commands.append(cmd)

    return {
        "entity_type": "user",
        "entity": clean,
        "total_events": len(events),
        "first_seen": events[-1].timestamp if events else None,
        "last_seen": events[0].timestamp if events else None,
        "event_types": by_type,
        "outcomes": by_outcome,
        "source_ips": sorted(source_ips)[:25],
        "hostnames": sorted(hostnames)[:20],
        "commands_executed": commands,
        "related_alerts": [
            {
                "id": str(a.id),
                "reference": a.reference,
                "rule_id": a.rule_id,
                "title": a.title,
                "severity": a.severity,
                "status": a.status,
                "created_at": a.created_at.isoformat(),
            }
            for a in alerts
        ],
    }


# ---------------------------------------------------------------------------
# Predefined hypothesis-driven hunts
# ---------------------------------------------------------------------------

HUNT_CATALOG: tuple[dict[str, Any], ...] = (
    {
        "id": "compromised_after_failures",
        "name": "Successful Login After Multiple Failures (Same Source IP)",
        "hypothesis": (
            "An adversary who guesses or sprays credentials may succeed after several "
            "failed attempts from the same IP address."
        ),
        "mitre_techniques": ["T1110.001", "T1110.003", "T1078"],
    },
    {
        "id": "multi_category_sources",
        "name": "Multi-Stage Source IPs (Active Across >= 2 Telemetry Categories)",
        "hypothesis": (
            "An external IP observed in multiple telemetry categories (e.g. firewall "
            "port scan followed by SSH login attempts or HTTP probes) indicates "
            "coordinated reconnaissance and exploitation."
        ),
        "mitre_techniques": ["T1046", "T1190", "T1110"],
    },
    {
        "id": "high_entropy_dns_hunt",
        "name": "Long or TXT DNS Queries (Low-and-Slow Tunneling Hunt)",
        "hypothesis": (
            "Adversaries may throttle DNS tunneling queries below volume alert thresholds; "
            "hunting for long query names (>= 45 chars) or TXT lookups surfaces stealthy channels."
        ),
        "mitre_techniques": ["T1071.004", "T1048"],
    },
    {
        "id": "suspicious_privilege_commands",
        "name": "Privileged Shell Commands & Account Changes",
        "hypothesis": (
            "Post-exploitation activity frequently involves sudo command execution, "
            "local user creation, credential file access or history tampering."
        ),
        "mitre_techniques": ["T1548.003", "T1136.001", "T1070.003"],
    },
    {
        "id": "web_error_and_probe_sources",
        "name": "HTTP Error & Vulnerability Probe Sources",
        "hypothesis": (
            "Sources generating concentrated HTTP 4xx/5xx responses are often running "
            "content discovery or vulnerability scanners."
        ),
        "mitre_techniques": ["T1595.002", "T1595.003", "T1190"],
    },
)

HUNT_BY_ID: dict[str, dict[str, Any]] = {h["id"]: h for h in HUNT_CATALOG}


def execute_predefined_hunt(db: Session, query_id: str) -> dict[str, Any]:
    meta = HUNT_BY_ID.get(query_id)
    if meta is None:
        raise NotFoundError(f"Hunt query {query_id!r} not found")

    if query_id == "compromised_after_failures":
        auth_rows = db.execute(
            select(
                SecurityEvent.source_ip,
                func.count().filter(SecurityEvent.event_outcome == "failure").label("failures"),
                func.count().filter(SecurityEvent.event_outcome == "success").label("successes"),
                func.array_agg(func.distinct(SecurityEvent.username)).label("users"),
                func.min(SecurityEvent.timestamp).label("first_seen"),
                func.max(SecurityEvent.timestamp).label("last_seen"),
            )
            .where(
                SecurityEvent.event_type == EventType.AUTHENTICATION.value,
                SecurityEvent.source_ip.is_not(None),
            )
            .group_by(SecurityEvent.source_ip)
            .having(
                func.count().filter(SecurityEvent.event_outcome == "failure") >= 3,
                func.count().filter(SecurityEvent.event_outcome == "success") >= 1,
            )
            .order_by(desc("failures"))
            .limit(50)
        ).all()
        results = [
            {
                "source_ip": str(r.source_ip),
                "failed_attempts": int(r.failures),
                "successful_logins": int(r.successes),
                "usernames": [u for u in (r.users or []) if u],
                "first_seen": r.first_seen.isoformat() if r.first_seen else None,
                "last_seen": r.last_seen.isoformat() if r.last_seen else None,
            }
            for r in auth_rows
        ]

    elif query_id == "multi_category_sources":
        cat_rows = db.execute(
            select(
                SecurityEvent.source_ip,
                func.count(func.distinct(SecurityEvent.event_type)).label("category_count"),
                func.array_agg(func.distinct(SecurityEvent.event_type)).label("categories"),
                func.count().label("total_events"),
                func.min(SecurityEvent.timestamp).label("first_seen"),
                func.max(SecurityEvent.timestamp).label("last_seen"),
            )
            .where(SecurityEvent.source_ip.is_not(None))
            .group_by(SecurityEvent.source_ip)
            .having(func.count(func.distinct(SecurityEvent.event_type)) >= 2)
            .order_by(desc("category_count"), desc("total_events"))
            .limit(50)
        ).all()
        results = [
            {
                "source_ip": str(r.source_ip),
                "category_count": int(r.category_count),
                "categories": sorted(r.categories or []),
                "total_events": int(r.total_events),
                "first_seen": r.first_seen.isoformat() if r.first_seen else None,
                "last_seen": r.last_seen.isoformat() if r.last_seen else None,
            }
            for r in cat_rows
        ]

    elif query_id == "high_entropy_dns_hunt":
        events = list(
            db.scalars(
                select(SecurityEvent)
                .where(SecurityEvent.event_type == EventType.DNS_QUERY.value)
                .order_by(SecurityEvent.timestamp.desc())
                .limit(300)
            )
        )
        results = []
        for ev in events:
            qname = str((ev.normalized_event or {}).get("dns.question.name") or "")
            qtype = str((ev.normalized_event or {}).get("dns.question.type") or "A")
            if len(qname) >= 45 or qtype == "TXT":
                results.append(
                    {
                        "event_id": str(ev.id),
                        "timestamp": ev.timestamp.isoformat(),
                        "source_ip": str(ev.source_ip) if ev.source_ip else None,
                        "query_name": qname,
                        "query_type": qtype,
                        "length": len(qname),
                    }
                )
            if len(results) >= 50:
                break

    elif query_id == "suspicious_privilege_commands":
        events = list(
            db.scalars(
                select(SecurityEvent)
                .where(SecurityEvent.event_type == EventType.PROCESS_EXECUTION.value)
                .order_by(SecurityEvent.timestamp.desc())
                .limit(100)
            )
        )
        results = [
            {
                "event_id": str(ev.id),
                "timestamp": ev.timestamp.isoformat(),
                "username": ev.username,
                "hostname": ev.hostname,
                "action": ev.event_action,
                "outcome": ev.event_outcome,
                "command": (ev.normalized_event or {}).get("process.command_line"),
                "target_user": (ev.normalized_event or {}).get("user.target.name"),
            }
            for ev in events
        ]

    else:  # web_error_and_probe_sources
        web_rows = db.execute(
            select(
                SecurityEvent.source_ip,
                func.count().label("total_requests"),
                func.count()
                .filter(SecurityEvent.event_outcome == EventOutcome.FAILURE.value)
                .label("error_requests"),
                func.min(SecurityEvent.timestamp).label("first_seen"),
                func.max(SecurityEvent.timestamp).label("last_seen"),
            )
            .where(
                SecurityEvent.event_type == EventType.HTTP_REQUEST.value,
                SecurityEvent.source_ip.is_not(None),
            )
            .group_by(SecurityEvent.source_ip)
            .having(
                func.count().filter(SecurityEvent.event_outcome == EventOutcome.FAILURE.value) >= 1
            )
            .order_by(desc("error_requests"))
            .limit(50)
        ).all()
        results = [
            {
                "source_ip": str(r.source_ip),
                "total_requests": int(r.total_requests),
                "error_requests": int(r.error_requests),
                "first_seen": r.first_seen.isoformat() if r.first_seen else None,
                "last_seen": r.last_seen.isoformat() if r.last_seen else None,
            }
            for r in web_rows
        ]

    return {
        "query": meta,
        "total_results": len(results),
        "results": results,
    }
