from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, CheckConstraint, DateTime, String, Uuid, text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, enum_check
from app.domain.enums import UserRole


class User(TimestampMixin, Base):
    """Platform user (SOC analyst). Not to be confused with usernames in logs."""

    __tablename__ = "users"
    __table_args__ = (
        enum_check("role", UserRole),
        CheckConstraint(r"username ~ '^[a-z0-9._-]{3,64}$'", name="username_format"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    display_name: Mapped[str] = mapped_column(String(128), nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(
        String(16), nullable=False, default=UserRole.ANALYST.value, server_default=text("'analyst'")
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default=text("true")
    )
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    @property
    def role_enum(self) -> UserRole:
        return UserRole(self.role)

    def __repr__(self) -> str:
        return f"<User {self.username} ({self.role})>"
