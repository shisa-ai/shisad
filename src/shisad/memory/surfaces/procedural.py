"""Procedural surface helpers for invocable memory artifacts."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Any

from shisad.security.firewall.output import OutputFirewall

if TYPE_CHECKING:
    from shisad.memory.schema import MemoryEntry

_PROCEDURAL_DESCRIPTION_MAX_CHARS = 120
_PROCEDURE_SECRET_FIREWALL = OutputFirewall(safe_domains=[])
_PROCEDURE_SCAN_PATTERNS: dict[str, re.Pattern[str]] = {
    "prompt_injection": re.compile(
        r"\b(ignore|override|discard).{0,48}\b(system|developer|instruction|policy)s?\b",
        re.IGNORECASE,
    ),
    "confirmation_bypass": re.compile(
        r"\b(skip|bypass|disable|avoid).{0,48}\b(confirm|approval|pep|safety|policy)\b",
        re.IGNORECASE,
    ),
    "credential_reference": re.compile(
        r"\b(api[_ -]?key|secret|password|credential|token)s?\b",
        re.IGNORECASE,
    ),
    "exfiltration": re.compile(
        r"\b(exfiltrate|send|upload|post).{0,48}\b"
        r"(secret|credential|token|password|api[_ -]?key)s?\b",
        re.IGNORECASE,
    ),
}


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
    prior_entry_id: str | None = None
    diff_preview: str | None = None


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


def scan_procedure_candidate_artifact(value: Any) -> dict[str, Any]:
    """Return a deterministic safety scan verdict for a procedural candidate."""

    text = _render_procedural_content(value)
    semantic_findings = {
        name for name, pattern in _PROCEDURE_SCAN_PATTERNS.items() if pattern.search(text)
    }
    secret_findings = set(_PROCEDURE_SECRET_FIREWALL.inspect(text).secret_findings)
    findings = sorted(semantic_findings | secret_findings)
    return {
        "verdict": "fail" if findings else "pass",
        "findings": findings,
    }


def build_procedure_trace_pool_hash(artifact: Any, trace_ids: list[str]) -> str:
    """Bind procedure-candidate provenance to the proposed artifact bytes."""

    normalized_trace_ids = [str(item).strip() for item in trace_ids if str(item).strip()]
    payload = {
        "artifact": _render_procedural_content(artifact),
        "trace_ids": normalized_trace_ids,
    }
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


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
