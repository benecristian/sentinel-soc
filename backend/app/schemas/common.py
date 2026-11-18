"""Shared schema building blocks."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

MAX_PAGE_SIZE = 200


class APIModel(BaseModel):
    """Base for response models (reads attributes from ORM objects)."""

    model_config = ConfigDict(from_attributes=True)


class StrictInput(BaseModel):
    """Base for request bodies: unknown fields are rejected, strings are trimmed."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class Page[T](BaseModel):
    items: list[T]
    total: int
    limit: int
    offset: int


class PaginationParams(BaseModel):
    limit: int = Field(default=50, ge=1, le=MAX_PAGE_SIZE)
    offset: int = Field(default=0, ge=0, le=1_000_000)


class MessageResponse(BaseModel):
    message: str
