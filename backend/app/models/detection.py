from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    Uuid,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, enum_check
from app.domain.enums import Severity
from app.models.mitre import MitreTechnique


class DetectionRule(TimestampMixin, Base):
    """Persisted configuration of a detection rule.

    The detection *logic* lives in code (app/detection/rules). This table holds the
    tunable configuration (enabled, threshold, window, parameters) and metadata,
    so analysts can tune rules without a redeploy, and every change is audited.
    """

    __tablename__ = "detection_rules"
    __table_args__ = (
        enum_check("severity", Severity),
        CheckConstraint(r"id ~ '^SENT-[A-Z]+-[0-9]{3}$'", name="id_format"),
        CheckConstraint("threshold BETWEEN 1 AND 100000", name="threshold_range"),
        CheckConstraint("time_window_seconds BETWEEN 10 AND 86400", name="time_window_range"),
        CheckConstraint("version >= 1", name="version_positive"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    category: Mapped[str] = mapped_column(String(32), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default=text("true")
    )
    threshold: Mapped[int] = mapped_column(Integer, nullable=False)
    time_window_seconds: Mapped[int] = mapped_column(Integer, nullable=False)
    parameters: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    investigation_steps: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, default=list, server_default=text("'[]'::jsonb")
    )
    remediation_steps: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, default=list, server_default=text("'[]'::jsonb")
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1, server_default="1")
    updated_by: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="SET NULL")
    )

    technique_links: Mapped[list[RuleTechnique]] = relationship(
        back_populates="rule", cascade="all, delete-orphan"
    )


class RuleTechnique(Base):
    """Maps a detection rule to MITRE ATT&CK techniques (exactly one primary per rule)."""

    __tablename__ = "rule_techniques"
    __table_args__ = (
        Index(
            "uq_rule_techniques_one_primary",
            "rule_id",
            unique=True,
            postgresql_where=text("is_primary"),
        ),
    )

    rule_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("detection_rules.id", ondelete="CASCADE"), primary_key=True
    )
    technique_id: Mapped[str] = mapped_column(
        String(16), ForeignKey("mitre_techniques.id", ondelete="CASCADE"), primary_key=True
    )
    is_primary: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )

    rule: Mapped[DetectionRule] = relationship(back_populates="technique_links")
    technique: Mapped[MitreTechnique] = relationship()
