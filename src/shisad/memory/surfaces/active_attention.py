"""Active Attention surface compiler helpers."""

from __future__ import annotations

import json
from collections import deque
from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING

from shisad.memory.remap import ACTIVE_AGENDA_ENTRY_TYPES

if TYPE_CHECKING:
    from shisad.memory.schema import MemoryEntry

DEFAULT_ACTIVE_ATTENTION_MAX_TOKENS = 750
ACTIVE_ATTENTION_WORKFLOW_STATES = {"active", "waiting", "blocked"}
ACTIVE_ATTENTION_CLASS_PRIORITY = (
    "waiting_on",
    "scheduled",
    "recurring",
    "open_thread",
    "inbox_item",
)
CHANNEL_AFFINED_ENTRY_TYPES = {
    "inbox_item",
    "channel_summary",
    "person_note",
    "channel_participation",
    "response_feedback",
}


def _estimate_attention_tokens(entry: MemoryEntry) -> int:
    value = entry.value
    if isinstance(value, str):
        rendered = value
    else:
        rendered = json.dumps(value, ensure_ascii=True, sort_keys=True, default=str)
    return max(1, len(f"{entry.key} {rendered}".split()))


@dataclass(slots=True)
class ActiveAttentionPack:
    """Selected active-agenda entries for the Active Attention surface."""

    entries: list[MemoryEntry]
    count: int
    citation_ids: list[str]
    used_tokens: int
    max_tokens: int
    scope_filter: set[str] | None
    channel_binding: str | None


def build_active_attention_pack(
    *,
    entries: list[MemoryEntry],
    max_tokens: int = DEFAULT_ACTIVE_ATTENTION_MAX_TOKENS,
    scope_filter: set[str] | None = None,
    allowed_channel_trusts: set[str] | None = None,
    channel_binding: str | None = None,
) -> ActiveAttentionPack:
    """Filter and budget active-agenda entries."""

    selected = sorted(
        (
            entry
            for entry in entries
            if entry.entry_type in ACTIVE_AGENDA_ENTRY_TYPES
            and entry.superseded_by is None
            and entry.status == "active"
            and entry.workflow_state in ACTIVE_ATTENTION_WORKFLOW_STATES
            and (scope_filter is None or entry.scope in scope_filter)
            and _passes_allowed_channel_trusts(
                entry=entry,
                allowed_channel_trusts=allowed_channel_trusts,
            )
            and _matches_channel_binding(entry, channel_binding)
        ),
        key=lambda entry: entry.created_at,
        reverse=True,
    )
    budgeted = _class_balance_attention_entries(selected)

    kept: list[MemoryEntry] = []
    used_tokens = 0
    for entry in budgeted:
        token_estimate = _estimate_attention_tokens(entry)
        if kept and used_tokens + token_estimate > max_tokens:
            continue
        kept.append(entry)
        used_tokens += token_estimate

    return ActiveAttentionPack(
        entries=kept,
        count=len(kept),
        citation_ids=[entry.id for entry in kept],
        used_tokens=used_tokens,
        max_tokens=max_tokens,
        scope_filter=set(scope_filter) if scope_filter is not None else None,
        channel_binding=channel_binding.strip() if channel_binding else None,
    )


def _passes_allowed_channel_trusts(
    *,
    entry: MemoryEntry,
    allowed_channel_trusts: set[str] | None,
) -> bool:
    if allowed_channel_trusts is None:
        return True
    if entry.scope != "channel":
        return True
    return entry.channel_trust in allowed_channel_trusts


def _matches_channel_binding(entry: MemoryEntry, channel_binding: str | None) -> bool:
    if channel_binding is None:
        return True
    entry_binding = _extract_channel_binding(entry)
    if entry_binding is None:
        return not _requires_channel_binding(entry)
    return _channel_bindings_match(entry_binding, channel_binding)


def _requires_channel_binding(entry: MemoryEntry) -> bool:
    return entry.scope == "channel" or entry.entry_type in CHANNEL_AFFINED_ENTRY_TYPES


def _extract_channel_binding(entry: MemoryEntry) -> str | None:
    value = entry.value
    if not isinstance(value, Mapping):
        return None
    raw_binding = value.get("channel_id")
    if not isinstance(raw_binding, str):
        return None
    binding = raw_binding.strip()
    return binding or None


def _channel_bindings_match(entry_binding: str, channel_binding: str) -> bool:
    normalized_entry = entry_binding.strip().lower()
    normalized_current = channel_binding.strip().lower()
    if not normalized_entry or not normalized_current:
        return False
    if normalized_entry == normalized_current:
        return True
    legacy_current = _legacy_channel_binding(normalized_current)
    return _is_legacy_bare_channel_binding(normalized_entry) and normalized_entry == legacy_current


def _is_legacy_bare_channel_binding(binding: str) -> bool:
    return ":" not in binding and "/" not in binding and "\\" not in binding


def _legacy_channel_binding(binding: str) -> str | None:
    normalized = binding.replace("\\", "/").strip().lower()
    if not normalized:
        return None
    if "/" in normalized:
        candidate = normalized.rsplit("/", 1)[-1].strip()
        return candidate or None
    if ":" in normalized:
        candidate = normalized.rsplit(":", 1)[-1].strip()
        return candidate or None
    return None


def _class_balance_attention_entries(entries: list[MemoryEntry]) -> list[MemoryEntry]:
    buckets: dict[str, deque[MemoryEntry]] = {
        entry_type: deque() for entry_type in ACTIVE_ATTENTION_CLASS_PRIORITY
    }
    remainder: list[MemoryEntry] = []
    for entry in entries:
        bucket = buckets.get(entry.entry_type)
        if bucket is None:
            remainder.append(entry)
            continue
        bucket.append(entry)

    ordered: list[MemoryEntry] = []
    while any(bucket for bucket in buckets.values()):
        for entry_type in ACTIVE_ATTENTION_CLASS_PRIORITY:
            bucket = buckets[entry_type]
            if bucket:
                ordered.append(bucket.popleft())
    ordered.extend(remainder)
    return ordered
