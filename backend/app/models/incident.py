from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Sequence,
    String,
    Text,
    UniqueConstraint,
    Uuid,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, enum_check
from app.domain.enums import IncidentStatus, Severity, TimelineEntryType
from app.models.user import User

incident_reference_seq = Sequence("incident_reference_seq", metadata=Base.metadata)


class Incident(TimestampMixin, Base):
    """A confirmed or suspected security incident grouping one or more alerts."""

    __tablename__ = "incidents"
    __table_args__ = (
        enum_check("severity", Severity),
        enum_check("status", IncidentStatus),
        Index("ix_incidents_status_severity", "status", "severity"),
        Index("ix_incidents_created_at", "created_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    reference: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        unique=True,
        server_default=text("'INC-' || lpad(nextval('incident_reference_seq')::text, 4, '0')"),
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default=IncidentStatus.OPEN.value, server_default="open"
    )
    lead_analyst_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="SET NULL")
    )
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="SET NULL")
    )
    recommended_actions: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, default=list, server_default=text("'[]'::jsonb")
    )
    findings: Mapped[str] = mapped_column(Text, nullable=False, default="", server_default="")
    resolution_summary: Mapped[str] = mapped_column(
        Text, nullable=False, default="", server_default=""
    )
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    lead_analyst: Mapped[User | None] = relationship(foreign_keys=[lead_analyst_id])
    alert_links: Mapped[list[IncidentAlert]] = relationship(
        back_populates="incident", cascade="all, delete-orphan"
    )
    timeline: Mapped[list[IncidentTimelineEntry]] = relationship(
        back_populates="incident",
        cascade="all, delete-orphan",
        order_by="IncidentTimelineEntry.occurred_at",
    )


class IncidentAlert(Base):
    """Association between incidents and alerts. An alert belongs to at most one incident."""

    __tablename__ = "incident_alerts"
    __table_args__ = (UniqueConstraint("alert_id", name="uq_incident_alerts_alert_id"),)

    incident_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("incidents.id", ondelete="CASCADE"), primary_key=True
    )
    alert_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("alerts.id", ondelete="CASCADE"), primary_key=True
    )
    added_by: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="SET NULL")
    )
    added_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    incident: Mapped[Incident] = relationship(back_populates="alert_links")


class IncidentTimelineEntry(Base):
    """Chronological record of everything that happened during an incident."""

    __tablename__ = "incident_timeline"
    __table_args__ = (
        enum_check("entry_type", TimelineEntryType),
        Index("ix_incident_timeline_incident_occurred", "incident_id", "occurred_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    incident_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False
    )
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    entry_type: Mapped[str] = mapped_column(String(20), nullable=False)
    summary: Mapped[str] = mapped_column(String(500), nullable=False)
    details: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    actor_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="SET NULL")
    )

    incident: Mapped[Incident] = relationship(back_populates="timeline")


class InvestigationNote(Base):
    """Analyst note attached to exactly one alert OR one incident."""

    __tablename__ = "investigation_notes"
    __table_args__ = (
        CheckConstraint("num_nonnulls(alert_id, incident_id) = 1", name="exactly_one_parent"),
        CheckConstraint("char_length(body) BETWEEN 1 AND 10000", name="body_length"),
        Index("ix_investigation_notes_alert_id", "alert_id"),
        Index("ix_investigation_notes_incident_id", "incident_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    alert_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("alerts.id", ondelete="CASCADE")
    )
    incident_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("incidents.id", ondelete="CASCADE")
    )
    author_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="SET NULL")
    )
    body: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    author: Mapped[User | None] = relationship()
