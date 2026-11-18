from __future__ import annotations

from sqlalchemy import CheckConstraint, Column, ForeignKey, Integer, String, Table, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

technique_tactics = Table(
    "technique_tactics",
    Base.metadata,
    Column(
        "technique_id",
        String(16),
        ForeignKey("mitre_techniques.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column(
        "tactic_id",
        String(16),
        ForeignKey("mitre_tactics.id", ondelete="CASCADE"),
        primary_key=True,
    ),
)


class MitreTactic(Base):
    """MITRE ATT&CK tactic (the adversary's goal, e.g. TA0006 Credential Access)."""

    __tablename__ = "mitre_tactics"
    __table_args__ = (CheckConstraint(r"id ~ '^TA[0-9]{4}$'", name="id_format"),)

    id: Mapped[str] = mapped_column(String(16), primary_key=True)
    name: Mapped[str] = mapped_column(String(64), nullable=False)
    shortname: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    url: Mapped[str] = mapped_column(String(255), nullable=False)
    display_order: Mapped[int] = mapped_column(Integer, nullable=False)

    techniques: Mapped[list[MitreTechnique]] = relationship(
        secondary=technique_tactics, back_populates="tactics"
    )


class MitreTechnique(Base):
    """MITRE ATT&CK technique or sub-technique (e.g. T1110.003 Password Spraying)."""

    __tablename__ = "mitre_techniques"
    __table_args__ = (CheckConstraint(r"id ~ '^T[0-9]{4}(\.[0-9]{3})?$'", name="id_format"),)

    id: Mapped[str] = mapped_column(String(16), primary_key=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    parent_id: Mapped[str | None] = mapped_column(
        String(16), ForeignKey("mitre_techniques.id", ondelete="CASCADE")
    )
    url: Mapped[str] = mapped_column(String(255), nullable=False)
    attack_version: Mapped[str] = mapped_column(String(16), nullable=False)

    tactics: Mapped[list[MitreTactic]] = relationship(
        secondary=technique_tactics, back_populates="techniques"
    )
