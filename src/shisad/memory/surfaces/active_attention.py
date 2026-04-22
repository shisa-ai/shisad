"""Active Attention surface compiler helpers."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TYPE_CHECKING

from shisad.memory.remap import ACTIVE_AGENDA_ENTRY_TYPES

if TYPE_CHECKING:
    from shisad.memory.schema import MemoryEntry

DEFAULT_ACTIVE_ATTENTION_MAX_TOKENS = 750
ACTIVE_ATTENTION_WORKFLOW_STATES = {"active", "waiting", "blocked"}


def _estimate_attention_tokens(entry: MemoryEntry) -> int:
    value = entry.value
    if isinstance(value, str):
        rendered = value
    else:
        rendered = json.dumps(value, ensure_ascii=True, sort_keys=True)
    return max(1, len(f"{entry.key} {rendered}".split()))


@dataclass(slots=True)
class ActiveAttentionPack:
    """Selected active-agenda entries for the Active Attention surface."""

    entries: list[MemoryEntry]
    count: int
    used_tokens: int
    max_tokens: int
    scope_filter: set[str] | None


def build_active_attention_pack(
    *,
    entries: list[MemoryEntry],
    max_tokens: int = DEFAULT_ACTIVE_ATTENTION_MAX_TOKENS,
    scope_filter: set[str] | None = None,
    allowed_channel_trusts: set[str] | None = None,
) -> ActiveAttentionPack:
    """Filter and budget active-agenda entries."""

    selected = sorted(
        (
            entry
            for entry in entries
            if entry.entry_type in ACTIVE_AGENDA_ENTRY_TYPES
            and entry.status == "active"
            and entry.workflow_state in ACTIVE_ATTENTION_WORKFLOW_STATES
            and (scope_filter is None or entry.scope in scope_filter)
            and (
                allowed_channel_trusts is None or entry.channel_trust in allowed_channel_trusts
            )
        ),
        key=lambda entry: entry.created_at,
        reverse=True,
    )

    kept: list[MemoryEntry] = []
    used_tokens = 0
    for entry in selected:
        token_estimate = _estimate_attention_tokens(entry)
        if kept and used_tokens + token_estimate > max_tokens:
            continue
        kept.append(entry)
        used_tokens += token_estimate

    return ActiveAttentionPack(
        entries=kept,
        count=len(kept),
        used_tokens=used_tokens,
        max_tokens=max_tokens,
        scope_filter=set(scope_filter) if scope_filter is not None else None,
    )
