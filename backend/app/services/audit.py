"""Append-only audit trail for security-relevant actions."""

from __future__ import annotations

import ipaddress
import uuid
from typing import Any

from sqlalchemy.orm import Session

from app.models import AuditLog


def _valid_ip_or_none(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def record_audit(
    db: Session,
    *,
    action: str,
    actor_id: uuid.UUID | None = None,
    target_type: str | None = None,
    target_id: str | uuid.UUID | None = None,
    changes: dict[str, Any] | None = None,
    client_ip: str | None = None,
) -> AuditLog:
    """Add an audit record to the current transaction (committed by the caller)."""
    entry = AuditLog(
        action=action,
        actor_id=actor_id,
        target_type=target_type,
        target_id=str(target_id) if target_id is not None else None,
        changes=changes or {},
        client_ip=_valid_ip_or_none(client_ip),
    )
    db.add(entry)
    return entry
