"""Typed value contracts and namespaces for shared participation memory."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal
from urllib.parse import quote

from pydantic import BaseModel, Field, field_validator


class AgentResponseSummary(BaseModel):
    """Compact record of one agent response in a shared channel."""

    timestamp: datetime
    message_id: str
    content_summary: str
    thread_id: str | None = None
    reaction_summary: dict[str, int] = Field(default_factory=dict)
    was_proactive: bool = False

    @field_validator("reaction_summary")
    @classmethod
    def _validate_reaction_summary(cls, value: dict[str, int]) -> dict[str, int]:
        if any(count < 0 for count in value.values()):
            raise ValueError("reaction_summary counts must be non-negative")
        return value


class TrackedThreadState(BaseModel):
    """Tracked thread/topic state for a shared channel."""

    thread_id: str
    topic_summary: str = ""
    last_activity: datetime | None = None
    my_participation_count: int = Field(default=0, ge=0)
    participants: list[str] = Field(default_factory=list)


class ScratchpadEntry(BaseModel):
    """Short-lived working note derived from recent channel activity."""

    timestamp: datetime
    content: str
    relevance_score: float = Field(default=0.0, ge=0.0, le=1.0)
    expiry: datetime | None = None


class InboxItemValue(BaseModel):
    """Durable owner inbox item stored on the shared substrate."""

    owner_id: str
    sender_id: str
    sender_display_name: str | None = None
    channel_id: str
    channel_name: str | None = None
    message_type: Literal["message_for_owner", "scheduling_request", "question", "task"] = (
        "message_for_owner"
    )
    body: str
    status: Literal["unread", "pending_response", "archived"] = "unread"
    priority: Literal["low", "normal", "high"] = "normal"
    received_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ChannelSummaryValue(BaseModel):
    """Periodic topic/digest summary for one shared channel."""

    channel_id: str
    guild_id: str = ""
    summary_kind: Literal["topic", "digest", "thread"] = "topic"
    summary_text: str
    window_start: datetime | None = None
    window_end: datetime | None = None
    source_message_ids: list[str] = Field(default_factory=list)


class PersonNoteValue(BaseModel):
    """Observed interaction profile for one participant in one channel."""

    external_user_id: str
    display_name: str
    channel_id: str
    role_notes: str = ""
    language_preferences: list[str] = Field(default_factory=list)
    topic_interests: list[str] = Field(default_factory=list)
    interaction_style: str = ""
    total_interactions: int = Field(default=0, ge=0)
    last_interaction: datetime | None = None
    interaction_summary: str = ""
    positive_reactions: int = Field(default=0, ge=0)
    negative_reactions: int = Field(default=0, ge=0)
    ignored_responses: int = Field(default=0, ge=0)
    thread_starts: int = Field(default=0, ge=0)


class ChannelParticipationStateValue(BaseModel):
    """Per-channel participation context assembled from structured records."""

    channel_id: str
    guild_id: str = ""
    my_responses: list[AgentResponseSummary] = Field(default_factory=list)
    tracked_threads: list[TrackedThreadState] = Field(default_factory=list)
    topic_summary: str = ""
    topic_summary_updated_at: datetime | None = None
    scratchpad: list[ScratchpadEntry] = Field(default_factory=list)


class ResponseFeedbackEventValue(BaseModel):
    """Observed feedback signal against an agent response."""

    channel_id: str
    target_message_id: str
    actor_external_user_id: str
    signal: Literal["reaction_add", "reaction_remove", "ignored_response"]
    emoji: str | None = None
    valence: Literal["positive", "negative", "neutral", "none"] = "none"
    observed_at: datetime
    was_proactive: bool | None = None
    thread_id: str | None = None


_STRUCTURED_ENTRY_MODELS: dict[str, type[BaseModel]] = {
    "inbox_item": InboxItemValue,
    "channel_summary": ChannelSummaryValue,
    "person_note": PersonNoteValue,
    "channel_participation": ChannelParticipationStateValue,
    "response_feedback": ResponseFeedbackEventValue,
}


def normalize_structured_memory_value(entry_type: str, value: Any) -> Any:
    """Validate and normalize typed participation payloads."""

    model = _STRUCTURED_ENTRY_MODELS.get(str(entry_type))
    if model is None:
        return value
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="python")
    return model.model_validate(value).model_dump(mode="python")


def inbox_item_key(*, owner_id: str, item_id: str) -> str:
    return _compose_key("inbox", owner_id, item_id)


def compose_channel_binding(*, channel: str, workspace_hint: str = "", channel_id: str) -> str:
    """Return a stable workspace-qualified binding for channel-affined records."""

    normalized_channel = str(channel).strip().lower()
    normalized_workspace = str(workspace_hint).strip()
    normalized_channel_id = str(channel_id).strip()
    if not normalized_channel_id:
        raise ValueError("channel_id must be non-empty")
    if normalized_workspace:
        return f"{normalized_channel}:{normalized_workspace}/{normalized_channel_id}"
    if normalized_channel:
        return f"{normalized_channel}:{normalized_channel_id}"
    return normalized_channel_id


def channel_summary_key(*, channel_id: str, summary_kind: str) -> str:
    return _compose_key("channel-summary", channel_id, summary_kind)


def person_note_key(*, channel_id: str, external_user_id: str) -> str:
    return _compose_key("person-note", channel_id, external_user_id)


def channel_participation_key(*, channel_id: str, thread_id: str | None = None) -> str:
    if thread_id is None:
        return _compose_key("channel-participation", channel_id)
    return _compose_key("channel-participation", channel_id, thread_id)


def response_feedback_key(
    *,
    channel_id: str,
    message_id: str,
    actor_external_user_id: str,
    signal: str,
) -> str:
    return _compose_key(
        "response-feedback",
        channel_id,
        message_id,
        actor_external_user_id,
        signal,
    )


def _compose_key(prefix: str, *parts: str) -> str:
    encoded_parts = [_encode_part(part) for part in parts]
    return ":".join((prefix, *encoded_parts))


def _encode_part(value: str) -> str:
    text = str(value).strip()
    if not text:
        raise ValueError("memory namespace parts must be non-empty")
    return quote(text, safe="-_.")
