"""Artifact lifecycle state machine for skills."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class ArtifactState(StrEnum):
    DRAFT = "draft"
    REVIEW = "review"
    PUBLISHED = "published"
    REVOKED = "revoked"


class RolloutMetadata(BaseModel):
    canary_percent: int = 100
    pinned_version: str = ""
    rollback_to: str = ""

    @property
    def is_canary(self) -> bool:
        return 0 < self.canary_percent < 100


class SkillArtifact(BaseModel):
    artifact_id: str
    name: str
    version: str
    state: ArtifactState = ArtifactState.DRAFT
    updated_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    rollout: RolloutMetadata = Field(default_factory=RolloutMetadata)
    history: list[dict[str, Any]] = Field(default_factory=list)

    def transition(self, *, action: str, actor: str, reason: str = "") -> ArtifactState:
        current = self.state
        next_state = _transition(current, action)
        if next_state == current:
            return current
        self.state = next_state
        self.updated_at = datetime.now(UTC).isoformat()
        self.history.append(
            {
                "from": current.value,
                "to": next_state.value,
                "action": action,
                "actor": actor,
                "reason": reason,
                "timestamp": self.updated_at,
            }
        )
        return next_state


def _transition(current: ArtifactState, action: str) -> ArtifactState:
    normalized = action.strip().lower()
    if current == ArtifactState.DRAFT and normalized == "submit":
        return ArtifactState.REVIEW
    if current == ArtifactState.REVIEW and normalized == "approve":
        return ArtifactState.PUBLISHED
    if current == ArtifactState.PUBLISHED and normalized == "revoke":
        return ArtifactState.REVOKED
    if current in {ArtifactState.DRAFT, ArtifactState.REVIEW} and normalized == "recall":
        return ArtifactState.DRAFT
    return current

