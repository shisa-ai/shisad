"""Identity surface compiler helpers."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from shisad.memory.schema import MemoryEntry

DEFAULT_IDENTITY_MAX_TOKENS = 750
IDENTITY_ENTRY_TYPES = {"persona_fact", "preference", "soft_constraint"}
IDENTITY_BLOCKED_SOURCE_ORIGINS = {
    "consolidation_derived",
    "external_message",
    "tool_output",
}


def _estimate_identity_tokens(entry: MemoryEntry) -> int:
    value = entry.value
    if isinstance(value, str):
        rendered = value
    else:
        rendered = json.dumps(value, ensure_ascii=True, sort_keys=True)
    return max(1, len(f"{entry.key} {rendered}".split()))


@dataclass(slots=True)
class IdentityPack:
    """Selected identity entries for the trusted user-authored region."""

    entries: list[MemoryEntry]
    count: int
    used_tokens: int
    max_tokens: int


def build_identity_pack(
    *,
    entries: list[MemoryEntry],
    max_tokens: int = DEFAULT_IDENTITY_MAX_TOKENS,
) -> IdentityPack:
    """Filter and budget elevated identity entries."""

    ranked = sorted(
        (
            entry
            for entry in entries
            if entry.entry_type in IDENTITY_ENTRY_TYPES
            and entry.trust_band == "elevated"
            and entry.source_origin not in IDENTITY_BLOCKED_SOURCE_ORIGINS
        ),
        key=lambda entry: (entry.importance_weight * entry.decay_score, entry.created_at),
        reverse=True,
    )

    kept: list[MemoryEntry] = []
    used_tokens = 0
    for entry in ranked:
        token_estimate = _estimate_identity_tokens(entry)
        if kept and used_tokens + token_estimate > max_tokens:
            continue
        kept.append(entry)
        used_tokens += token_estimate

    return IdentityPack(
        entries=kept,
        count=len(kept),
        used_tokens=used_tokens,
        max_tokens=max_tokens,
    )
