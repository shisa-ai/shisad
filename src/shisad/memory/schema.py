"""Canonical memory schemas with v0.7 legacy backfill."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator

from shisad.core.types import TaintLabel
from shisad.memory.participation import normalize_structured_memory_value
from shisad.memory.remap import remap_memory_entry_payload
from shisad.memory.trust import (
    ChannelTrust,
    ConfirmationStatus,
    SourceOrigin,
    TrustBand,
    derive_trust_band,
)

LegacyMemoryOrigin = Literal["user", "inferred", "external", "user_curated", "project_doc"]
MemoryEntryType = Literal[
    "persona_fact",
    "preference",
    "soft_constraint",
    "open_thread",
    "scheduled",
    "recurring",
    "waiting_on",
    "fact",
    "decision",
    "relationship",
    "episode",
    "note",
    "todo",
    "project_state",
    "inbox_item",
    "channel_summary",
    "person_note",
    "channel_participation",
    "response_feedback",
    "skill",
    "runbook",
    "template",
]
MemoryStatus = Literal["active", "quarantined", "tombstoned", "hard_deleted"]
WorkflowState = Literal["active", "waiting", "blocked", "stale", "closed"]
MemoryScope = Literal["user", "project", "session", "channel", "workspace"]
PreferenceStrength = Literal["weak", "moderate", "strong"]


class MemorySource(BaseModel):
    """Compatibility provenance view retained for the v0.6 API surface."""

    origin: LegacyMemoryOrigin
    source_id: str
    extraction_method: str


class MemoryEntry(BaseModel):
    """Long-term memory record with canonical v0.7 metadata."""

    id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    version: int = 1
    supersedes: str | None = None
    superseded_by: str | None = None

    entry_type: MemoryEntryType
    key: str
    value: Any
    predicate: str | None = None
    strength: PreferenceStrength = "moderate"

    source: MemorySource
    source_origin: SourceOrigin
    channel_trust: ChannelTrust
    confirmation_status: ConfirmationStatus
    source_id: str = ""

    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    valid_from: datetime | None = None
    valid_to: datetime | None = None
    last_verified_at: datetime | None = None
    expires_at: datetime | None = None

    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    taint_labels: list[TaintLabel] = Field(default_factory=list)
    citation_count: int = 0
    last_cited_at: datetime | None = None
    decay_score: float = Field(default=1.0, ge=0.0, le=1.0)
    importance_weight: float = Field(default=1.0, ge=0.0)

    status: MemoryStatus = "active"
    workflow_state: WorkflowState | None = None
    scope: MemoryScope = "user"
    # (user, workspace) ownership added in v0.7.1 C2 to close cross-session
    # recall leakage (see planning/PLAN-lockdown-no-deadend.md §4.4). Kept
    # optional so pre-migration rows and synthetic test fixtures remain
    # constructible; the write paths populate both fields from session
    # identity, and the read path excludes NULL-owner rows by default.
    user_id: str | None = None
    workspace_id: str | None = None
    invocation_eligible: bool = False
    ingress_handle_id: str | None = None
    content_digest: str | None = None
    conflict_entry_ids: list[str] = Field(default_factory=list)

    # Legacy compatibility fields kept while the handler/API surface is still v0.6-shaped.
    user_verified: bool = False
    deleted_at: datetime | None = None
    quarantined: bool = False

    @model_validator(mode="before")
    @classmethod
    def _backfill_legacy_shape(cls, payload: Any) -> Any:
        if isinstance(payload, BaseModel):
            payload = payload.model_dump(mode="python")
        if isinstance(payload, dict):
            return remap_memory_entry_payload(payload)
        return payload

    @model_validator(mode="after")
    def _normalize_structured_payloads(self) -> MemoryEntry:
        self.value = normalize_structured_memory_value(str(self.entry_type), self.value)
        return self

    @property
    def entry_id(self) -> str:
        return self.id

    @property
    def trust_band(self) -> TrustBand:
        return derive_trust_band(
            self.source_origin,
            self.channel_trust,
            self.confirmation_status,
        )


class MemoryWriteDecision(BaseModel):
    kind: Literal["allow", "reject", "require_confirmation"]
    reason: str = ""
    entry: MemoryEntry | None = None
