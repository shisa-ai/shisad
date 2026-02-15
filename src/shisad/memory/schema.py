"""Memory manager schemas."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

from shisad.core.types import TaintLabel


class MemorySource(BaseModel):
    """Attribution metadata for a stored memory entry."""

    origin: Literal["user", "inferred", "external"]
    source_id: str
    extraction_method: str


class MemoryEntry(BaseModel):
    """Long-term memory record (facts/preferences/context/note/todo)."""

    id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    entry_type: Literal["fact", "preference", "context", "note", "todo"]
    key: str
    value: Any
    source: MemorySource
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime | None = None
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    user_verified: bool = False
    deleted_at: datetime | None = None
    quarantined: bool = False
    taint_labels: list[TaintLabel] = Field(default_factory=list)


class MemoryWriteDecision(BaseModel):
    kind: Literal["allow", "reject", "require_confirmation"]
    reason: str = ""
    entry: MemoryEntry | None = None
