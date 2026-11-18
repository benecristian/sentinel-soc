from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import Field

from app.domain.enums import UserRole
from app.schemas.common import APIModel, StrictInput


class LoginRequest(StrictInput):
    username: str = Field(min_length=3, max_length=64)
    # No complexity checks at login (that would leak the policy); just sane bounds.
    password: str = Field(min_length=1, max_length=128)


class UserRead(APIModel):
    id: uuid.UUID
    username: str
    display_name: str
    role: UserRole
    is_active: bool
    last_login_at: datetime | None = None


class UserSummary(APIModel):
    id: uuid.UUID
    username: str
    display_name: str
    role: UserRole
