"""Legacy-to-canonical remap helpers for v0.7 memory entries."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from datetime import date, datetime
from typing import Any

from pydantic import BaseModel

from shisad.memory.trust import SourceOrigin, TrustGateViolation, backfill_legacy_triple

ACTIVE_AGENDA_ENTRY_TYPES = {"open_thread", "scheduled", "recurring", "waiting_on", "inbox_item"}
PROCEDURAL_ENTRY_TYPES = {"skill", "runbook", "template"}

_TEMPORAL_MARKERS = re.compile(
    r"\b(?:\d{4}-\d{2}-\d{2}|"
    r"\d{1,2}:\d{2}|"
    r"today|yesterday|tomorrow|"
    r"monday|tuesday|wednesday|thursday|friday|saturday|sunday|"
    r"january|february|march|april|may|june|july|august|september|october|"
    r"november|december|"
    r"last|next)\b",
    re.IGNORECASE,
)
_EVENT_VERBS = re.compile(
    r"\b(?:met|meeting|discussed|reviewed|planned|decided|called|talked|"
    r"spoke|launched|shipped|arrived|went|moved|joined|left)\b",
    re.IGNORECASE,
)


def digest_memory_value(value: Any) -> str:
    """Return a stable digest for arbitrary memory-entry values."""

    if isinstance(value, str):
        payload = value
    else:
        payload = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            default=_json_default,
        )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def resolve_legacy_source_origin(
    legacy_origin: str,
    *,
    source_id: str = "",
    extraction_method: str = "",
) -> SourceOrigin:
    """Resolve legacy origin metadata to a conservative v0.7 source origin."""

    normalized_origin = legacy_origin.strip().lower()
    if normalized_origin in {"user", "user_curated"}:
        hint = f"{source_id}|{extraction_method}".lower()
        if any(token in hint for token in ("confirm", "confirmed", "approval", "approved")):
            return "user_confirmed"
        return "user_direct"
    if normalized_origin == "inferred":
        return "consolidation_derived"
    if normalized_origin == "external":
        return "external_web"
    if normalized_origin == "project_doc":
        return "tool_output"
    if normalized_origin in {
        "user_direct",
        "user_confirmed",
        "user_corrected",
        "tool_output",
        "external_web",
        "external_message",
        "consolidation_derived",
        "rc_evidence",
    }:
        return normalized_origin  # type: ignore[return-value]
    raise TrustGateViolation(f"unknown legacy origin: {legacy_origin}")


def legacy_source_view_origin(source_origin: SourceOrigin) -> str:
    """Return the compatibility `MemorySource.origin` view for a v0.7 source origin."""

    if source_origin in {"user_direct", "user_confirmed", "user_corrected"}:
        return "user"
    if source_origin == "consolidation_derived":
        return "inferred"
    return "external"


def remap_memory_entry_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Backfill missing v0.7 fields from legacy entry shapes."""

    data = dict(payload)
    source_id = str(data.get("source_id", "") or "")
    source = _normalize_source(data.get("source"), source_id=source_id)

    explicit_origin = data.get("source_origin")
    if explicit_origin:
        resolved_origin = resolve_legacy_source_origin(
            str(explicit_origin),
            source_id=source["source_id"],
            extraction_method=source["extraction_method"],
        )
    else:
        resolved_origin = resolve_legacy_source_origin(
            source["origin"],
            source_id=source["source_id"],
            extraction_method=source["extraction_method"],
        )
    resolved_origin, channel_trust, confirmation_status = backfill_legacy_triple(
        source_origin=resolved_origin,
        channel_trust=_optional_string(data.get("channel_trust")),  # type: ignore[arg-type]
        confirmation_status=_optional_string(data.get("confirmation_status")),  # type: ignore[arg-type]
    )

    data["source"] = source
    data["source_id"] = source_id or source["source_id"]
    data["source_origin"] = resolved_origin
    data["channel_trust"] = channel_trust
    data["confirmation_status"] = confirmation_status
    data["entry_type"] = _normalize_entry_type(
        str(data.get("entry_type", "fact")),
        data.get("value"),
    )
    data["scope"] = _optional_string(data.get("scope")) or "user"
    data["status"] = _optional_string(data.get("status")) or _resolve_status(data)
    data["workflow_state"] = _resolve_workflow_state(
        data["entry_type"],
        _optional_string(data.get("workflow_state")),
    )
    data["version"] = int(data.get("version", 1) or 1)
    data["supersedes"] = _optional_string(data.get("supersedes"))
    data["superseded_by"] = _optional_string(data.get("superseded_by"))
    data["last_verified_at"] = data.get("last_verified_at") or (
        data.get("created_at") if bool(data.get("user_verified")) else None
    )
    data["citation_count"] = int(data.get("citation_count", 0) or 0)
    data["last_cited_at"] = data.get("last_cited_at")
    data["decay_score"] = float(data.get("decay_score", 1.0) or 1.0)
    data["importance_weight"] = float(data.get("importance_weight", 1.0) or 1.0)
    data["invocation_eligible"] = bool(data.get("invocation_eligible", False))
    data["ingress_handle_id"] = _optional_string(data.get("ingress_handle_id"))
    data["content_digest"] = _optional_string(data.get("content_digest")) or digest_memory_value(
        data.get("value")
    )

    data["user_verified"] = bool(data.get("user_verified")) or data["last_verified_at"] is not None
    data["quarantined"] = data["status"] == "quarantined" or bool(data.get("quarantined", False))
    return data


def _json_default(value: Any) -> str:
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    return str(value)


def _normalize_source(source: Any, *, source_id: str) -> dict[str, str]:
    if isinstance(source, BaseModel):
        source = source.model_dump(mode="python")
    if isinstance(source, Mapping):
        return {
            "origin": str(source.get("origin", "user") or "user"),
            "source_id": str(source.get("source_id", source_id) or source_id),
            "extraction_method": str(source.get("extraction_method", "legacy") or "legacy"),
        }

    return {
        "origin": "external",
        "source_id": source_id,
        "extraction_method": "v0.7",
    }


def _normalize_entry_type(entry_type: str, value: Any) -> str:
    normalized = entry_type.strip().lower() or "fact"
    if normalized != "context":
        return normalized
    text = _value_as_text(value)
    if _TEMPORAL_MARKERS.search(text) or _EVENT_VERBS.search(text):
        return "episode"
    return "note"


def _resolve_status(data: Mapping[str, Any]) -> str:
    if data.get("deleted_at") is not None:
        return "tombstoned"
    if bool(data.get("quarantined", False)):
        return "quarantined"
    return "active"


def _resolve_workflow_state(entry_type: str, workflow_state: str | None) -> str | None:
    if entry_type in ACTIVE_AGENDA_ENTRY_TYPES:
        return workflow_state or "active"
    return workflow_state or None


def _optional_string(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _value_as_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, sort_keys=True, ensure_ascii=False, default=_json_default)
    except TypeError:
        return str(value)
