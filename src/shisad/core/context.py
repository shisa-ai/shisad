"""Episode-aware context models and helpers for v0.3.5 scaffolding."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

from pydantic import BaseModel, Field

from shisad.core.transcript import TranscriptEntry
from shisad.core.types import TaintLabel

DEFAULT_EPISODE_GAP_THRESHOLD = timedelta(hours=4)
DEFAULT_INTERNAL_TIER_TOKEN_BUDGET = 2048


class EpisodeSummary(BaseModel):
    """Compact deterministic summary for a conversation episode."""

    text: str = ""
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    minimized: bool = False


class EpisodeMessage(BaseModel):
    """Single turn payload used for episode grouping."""

    role: str
    content: str = ""
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    taint_labels: list[TaintLabel] = Field(default_factory=list)
    tool_names: list[str] = Field(default_factory=list)


class ConversationEpisode(BaseModel):
    """Logical group of transcript entries separated by temporal gaps."""

    episode_id: str = ""
    start_ts: datetime = Field(default_factory=lambda: datetime.now(UTC))
    end_ts: datetime = Field(default_factory=lambda: datetime.now(UTC))
    messages: list[EpisodeMessage] = Field(default_factory=list)
    message_count: int = 0
    finalized: bool = False
    summary: EpisodeSummary | None = None
    compressed: bool = False
    source_taint_labels: list[TaintLabel] = Field(default_factory=list)


class EpisodeCompressionResult(BaseModel):
    """Result of applying the Internal-tier episode token budget."""

    episodes: list[ConversationEpisode] = Field(default_factory=list)
    compressed_episode_ids: list[str] = Field(default_factory=list)
    evicted_episode_ids: list[str] = Field(default_factory=list)
    used_tokens: int = 0


class ContextScaffoldEntry(BaseModel):
    """Single context block within the three-tier scaffold."""

    entry_id: str = ""
    trust_level: str = "UNTRUSTED"
    content: str = ""
    provenance: list[str] = Field(default_factory=list)
    source_taint_labels: list[str] = Field(default_factory=list)


class ContextScaffold(BaseModel):
    """Top-level context scaffold container."""

    session_id: str = ""
    episodes: list[ConversationEpisode] = Field(default_factory=list)
    trusted_frontmatter: str = ""
    internal_entries: list[ContextScaffoldEntry] = Field(default_factory=list)
    untrusted_entries: list[ContextScaffoldEntry] = Field(default_factory=list)


def _normalize_timestamp(timestamp: datetime) -> datetime:
    if timestamp.tzinfo is None:
        return timestamp.replace(tzinfo=UTC)
    return timestamp.astimezone(UTC)


def _extract_tool_names(metadata: dict[str, Any]) -> list[str]:
    names: list[str] = []
    raw_names = metadata.get("tool_names")
    if isinstance(raw_names, list):
        for raw in raw_names:
            value = str(raw).strip()
            if value:
                names.append(value)
    raw_single = metadata.get("tool_name")
    if isinstance(raw_single, str):
        value = raw_single.strip()
        if value:
            names.append(value)
    return sorted(set(names))


def _entry_to_episode_message(entry: TranscriptEntry) -> EpisodeMessage:
    metadata = entry.metadata if isinstance(entry.metadata, dict) else {}
    return EpisodeMessage(
        role=entry.role,
        content=entry.content_preview,
        timestamp=_normalize_timestamp(entry.timestamp),
        taint_labels=list(entry.taint_labels),
        tool_names=_extract_tool_names(metadata),
    )


def _deterministic_summary_line(episode: ConversationEpisode) -> str:
    """Build one-line deterministic episode summary before message compaction."""
    role_counts: dict[str, int] = {}
    tool_names: set[str] = set()
    for message in episode.messages:
        role = message.role.strip().lower() or "unknown"
        role_counts[role] = role_counts.get(role, 0) + 1
        tool_names.update(message.tool_names)
    role_fragment = ",".join(
        f"{role}:{role_counts[role]}"
        for role in sorted(role_counts)
    ) or "none"
    tools_fragment = ",".join(sorted(tool_names)) if tool_names else "none"
    start = _normalize_timestamp(episode.start_ts).isoformat(timespec="seconds")
    end = _normalize_timestamp(episode.end_ts).isoformat(timespec="seconds")
    return (
        f"range={start}..{end} turns={episode.message_count} "
        f"roles={role_fragment} tools={tools_fragment}"
    )


def _episode_text_for_budget(episode: ConversationEpisode) -> str:
    if episode.compressed and episode.summary is not None:
        return episode.summary.text
    lines: list[str] = []
    for message in episode.messages:
        content = " ".join(message.content.split())
        lines.append(f"{message.role}: {content}")
    return "\n".join(lines)


def _estimate_tokens(text: str) -> int:
    compact = " ".join(text.split())
    if not compact:
        return 0
    # Rule-of-thumb approximation keeps budget behavior deterministic.
    return max(1, (len(compact) + 3) // 4)


def _episode_token_cost(episode: ConversationEpisode) -> int:
    return _estimate_tokens(_episode_text_for_budget(episode))


def _episode_taint_union(messages: Sequence[EpisodeMessage]) -> list[TaintLabel]:
    labels: set[TaintLabel] = set()
    for message in messages:
        labels.update(message.taint_labels)
    return sorted(labels)


def build_conversation_episodes(
    entries: Sequence[TranscriptEntry],
    *,
    gap_threshold: timedelta = DEFAULT_EPISODE_GAP_THRESHOLD,
) -> list[ConversationEpisode]:
    """Build conversation episodes using a gap-only heuristic."""
    if gap_threshold <= timedelta(0):
        raise ValueError("gap_threshold must be positive")
    if not entries:
        return []

    episodes: list[ConversationEpisode] = []
    episode_counter = 0
    current: ConversationEpisode | None = None

    for entry in entries:
        message = _entry_to_episode_message(entry)
        if current is None:
            episode_counter += 1
            current = ConversationEpisode(
                episode_id=f"ep-{episode_counter:04d}",
                start_ts=message.timestamp,
                end_ts=message.timestamp,
                messages=[message],
                message_count=1,
                finalized=False,
                source_taint_labels=list(message.taint_labels),
            )
            continue

        gap = message.timestamp - current.end_ts
        if gap >= gap_threshold:
            current.finalized = True
            current.summary = EpisodeSummary(
                text=_deterministic_summary_line(current),
                minimized=False,
            )
            current.source_taint_labels = _episode_taint_union(current.messages)
            episodes.append(current)
            episode_counter += 1
            current = ConversationEpisode(
                episode_id=f"ep-{episode_counter:04d}",
                start_ts=message.timestamp,
                end_ts=message.timestamp,
                messages=[message],
                message_count=1,
                finalized=False,
                source_taint_labels=list(message.taint_labels),
            )
            continue

        current.messages.append(message)
        current.message_count += 1
        current.end_ts = message.timestamp
        current.source_taint_labels = _episode_taint_union(current.messages)

    if current is not None:
        current.finalized = False
        current.source_taint_labels = _episode_taint_union(current.messages)
        episodes.append(current)
    return episodes


def compress_episodes_to_budget(
    episodes: Sequence[ConversationEpisode],
    *,
    token_budget: int = DEFAULT_INTERNAL_TIER_TOKEN_BUDGET,
) -> EpisodeCompressionResult:
    """Apply fixed-budget adaptive compression to finalized episodes.

    Compression order is oldest-first over finalized episodes. Active episodes
    are never compressed. If compressed summaries still exceed the budget,
    oldest finalized summaries are evicted (FIFO).
    """
    budget = max(1, int(token_budget))
    working = [episode.model_copy(deep=True) for episode in episodes]

    def _current_cost() -> int:
        return sum(_episode_token_cost(episode) for episode in working)

    compressed_episode_ids: list[str] = []
    evicted_episode_ids: list[str] = []

    used_tokens = _current_cost()
    if used_tokens <= budget:
        return EpisodeCompressionResult(
            episodes=working,
            compressed_episode_ids=compressed_episode_ids,
            evicted_episode_ids=evicted_episode_ids,
            used_tokens=used_tokens,
        )

    for episode in working:
        if used_tokens <= budget:
            break
        if not episode.finalized:
            continue
        if episode.compressed:
            continue
        episode.summary = EpisodeSummary(
            text=_deterministic_summary_line(episode),
            minimized=True,
        )
        episode.compressed = True
        episode.messages = []
        compressed_episode_ids.append(episode.episode_id)
        used_tokens = _current_cost()

    while used_tokens > budget:
        removable_index: int | None = None
        for index, episode in enumerate(working):
            if episode.finalized and episode.compressed:
                removable_index = index
                break
        if removable_index is None:
            break
        evicted_episode_ids.append(working[removable_index].episode_id)
        del working[removable_index]
        used_tokens = _current_cost()

    return EpisodeCompressionResult(
        episodes=working,
        compressed_episode_ids=compressed_episode_ids,
        evicted_episode_ids=evicted_episode_ids,
        used_tokens=used_tokens,
    )
