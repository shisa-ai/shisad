"""Procedural surface helpers for invocable memory artifacts."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from shisad.memory.schema import MemoryEntry

_PROCEDURAL_DESCRIPTION_MAX_CHARS = 120


@dataclass(slots=True)
class ProceduralArtifactSummary:
    id: str
    entry_type: str
    key: str
    name: str
    description: str
    trust_band: str
    last_used_at: datetime | None
    invocation_eligible: bool


@dataclass(slots=True)
class ProceduralArtifact:
    id: str
    entry_type: str
    key: str
    name: str
    description: str
    content: str
    trust_band: str
    source_origin: str
    channel_trust: str
    confirmation_status: str
    last_used_at: datetime | None
    size_bytes: int
    invocation_eligible: bool


@dataclass(slots=True)
class ProceduralInvocation:
    skill_id: str
    found: bool
    invoked: bool
    reason: str = ""
    artifact: ProceduralArtifact | None = None


def _render_procedural_content(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, str):
        return value
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False, default=str)


def _procedural_name(entry: MemoryEntry) -> str:
    key = str(entry.key).strip()
    prefix = f"{entry.entry_type}:"
    if key.lower().startswith(prefix):
        candidate = key[len(prefix) :].strip()
        if candidate:
            return candidate
    return key or entry.id


def _procedural_description(entry: MemoryEntry) -> str:
    content = _render_procedural_content(entry.value)
    meaningful_lines: list[str] = []
    for line in content.splitlines():
        normalized = line.strip().lstrip("#").strip()
        if normalized:
            meaningful_lines.append(normalized)
        if len(meaningful_lines) >= 2:
            break
    if meaningful_lines:
        return " | ".join(meaningful_lines)[:_PROCEDURAL_DESCRIPTION_MAX_CHARS]
    return _procedural_name(entry)


def build_procedural_summary(entry: MemoryEntry) -> ProceduralArtifactSummary:
    return ProceduralArtifactSummary(
        id=entry.id,
        entry_type=str(entry.entry_type),
        key=str(entry.key),
        name=_procedural_name(entry),
        description=_procedural_description(entry),
        trust_band=str(entry.trust_band),
        last_used_at=entry.last_cited_at,
        invocation_eligible=bool(entry.invocation_eligible),
    )


def build_procedural_artifact(entry: MemoryEntry) -> ProceduralArtifact:
    content = _render_procedural_content(entry.value)
    return ProceduralArtifact(
        id=entry.id,
        entry_type=str(entry.entry_type),
        key=str(entry.key),
        name=_procedural_name(entry),
        description=_procedural_description(entry),
        content=content,
        trust_band=str(entry.trust_band),
        source_origin=str(entry.source_origin),
        channel_trust=str(entry.channel_trust),
        confirmation_status=str(entry.confirmation_status),
        last_used_at=entry.last_cited_at,
        size_bytes=len(content.encode("utf-8")),
        invocation_eligible=bool(entry.invocation_eligible),
    )
