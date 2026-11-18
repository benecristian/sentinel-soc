from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    Uuid,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import INET, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, enum_check
from app.domain.enums import EventOutcome, EventType, IngestionSourceKind, Severity


class IngestionBatch(Base):
    """One ingestion operation (file upload, API batch or simulation) and its statistics."""

    __tablename__ = "ingestion_batches"
    __table_args__ = (
        enum_check("source_kind", IngestionSourceKind),
        CheckConstraint(
            "received_count >= 0 AND accepted_count >= 0 AND rejected_count >= 0 "
            "AND duplicate_count >= 0 AND ignored_count >= 0",
            name="counts_non_negative",
        ),
        Index("ix_ingestion_batches_started_at", "started_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    source_kind: Mapped[str] = mapped_column(String(16), nullable=False)
    original_filename: Mapped[str | None] = mapped_column(String(255))
    parser: Mapped[str] = mapped_column(String(32), nullable=False)
    received_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    accepted_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    rejected_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    duplicate_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    ignored_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    events_start: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    events_end: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    alerts_created: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    alerts_updated: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    error_samples: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, nullable=False, default=list, server_default=text("'[]'::jsonb")
    )
    simulation_run_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("simulation_runs.id", ondelete="SET NULL")
    )
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="SET NULL")
    )
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class SecurityEvent(Base):
    """A normalized security event. `timestamp` is the event time taken from the log."""

    __tablename__ = "security_events"
    __table_args__ = (
        enum_check("event_type", EventType),
        enum_check("event_outcome", EventOutcome),
        enum_check("severity", Severity),
        CheckConstraint(
            "source_port IS NULL OR source_port BETWEEN 0 AND 65535", name="source_port_range"
        ),
        CheckConstraint(
            "destination_port IS NULL OR destination_port BETWEEN 0 AND 65535",
            name="destination_port_range",
        ),
        CheckConstraint("char_length(raw_event) <= 65536", name="raw_event_length"),
        Index("ix_security_events_timestamp", "timestamp"),
        Index("ix_security_events_type_timestamp", "event_type", "timestamp"),
        Index("ix_security_events_source_ip", "source_ip"),
        Index("ix_security_events_destination_ip", "destination_ip"),
        Index("ix_security_events_username", "username"),
        Index("ix_security_events_hostname", "hostname"),
        Index("ix_security_events_ingestion_batch_id", "ingestion_batch_id"),
        Index(
            "ix_security_events_normalized_event",
            "normalized_event",
            postgresql_using="gin",
            postgresql_ops={"normalized_event": "jsonb_path_ops"},
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    ingestion_batch_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("ingestion_batches.id", ondelete="CASCADE")
    )
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    ingested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    event_type: Mapped[str] = mapped_column(String(32), nullable=False)
    event_action: Mapped[str | None] = mapped_column(String(64))
    event_outcome: Mapped[str] = mapped_column(
        String(16), nullable=False, default=EventOutcome.UNKNOWN.value, server_default="unknown"
    )
    severity: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default=Severity.INFORMATIONAL.value,
        server_default="informational",
    )
    source_ip: Mapped[str | None] = mapped_column(INET)
    destination_ip: Mapped[str | None] = mapped_column(INET)
    source_port: Mapped[int | None] = mapped_column(Integer)
    destination_port: Mapped[int | None] = mapped_column(Integer)
    protocol: Mapped[str | None] = mapped_column(String(16))
    username: Mapped[str | None] = mapped_column(String(256))
    hostname: Mapped[str | None] = mapped_column(String(255))
    service: Mapped[str | None] = mapped_column(String(64))
    log_source: Mapped[str] = mapped_column(String(32), nullable=False)
    raw_event: Mapped[str] = mapped_column(Text, nullable=False)
    normalized_event: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    is_synthetic: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    event_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
