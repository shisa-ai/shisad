"""Context scaffold model stubs for v0.3.5 follow-on wiring."""

from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel, Field


class EpisodeSummary(BaseModel):
    """Compact summary for a conversation episode."""

    text: str = ""
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ConversationEpisode(BaseModel):
    """Logical group of transcript entries."""

    episode_id: str = ""
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    ended_at: datetime | None = None
    summary: EpisodeSummary | None = None


class ContextScaffold(BaseModel):
    """Top-level context scaffold container."""

    session_id: str = ""
    episodes: list[ConversationEpisode] = Field(default_factory=list)
