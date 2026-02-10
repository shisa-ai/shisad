"""Separate control-plane audit stream with independent hash chain."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from shisad.security.control_plane.schema import sanitize_metadata_payload

_GENESIS_HASH = hashlib.sha256(b"shisad-control-plane-audit-genesis").hexdigest()


class ControlPlaneAuditEntry(BaseModel, frozen=True):
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    event_type: str
    session_id: str = ""
    actor: str = ""
    data: dict[str, Any] = Field(default_factory=dict)
    data_hash: str
    previous_hash: str


class ControlPlaneAuditLog:
    """Append-only metadata-only audit log for M5 control-plane decisions."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._previous_hash = _GENESIS_HASH
        self._entry_count = 0
        self._resume()

    @property
    def entry_count(self) -> int:
        return self._entry_count

    @property
    def path(self) -> Path:
        return self._path

    def append(self, *, event_type: str, session_id: str, actor: str, data: dict[str, Any]) -> None:
        cleaned = sanitize_metadata_payload(data)
        encoded_data = json.dumps(cleaned, sort_keys=True)
        data_hash = hashlib.sha256(encoded_data.encode("utf-8")).hexdigest()
        entry = ControlPlaneAuditEntry(
            event_type=event_type,
            session_id=session_id,
            actor=actor,
            data=cleaned,
            data_hash=data_hash,
            previous_hash=self._previous_hash,
        )
        payload = entry.model_dump_json()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._path.open("a", encoding="utf-8") as handle:
            handle.write(payload + "\n")
        self._previous_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        self._entry_count += 1

    def verify_chain(self) -> tuple[bool, int, str]:
        if not self._path.exists():
            return (True, 0, "")
        previous = _GENESIS_HASH
        count = 0
        with self._path.open(encoding="utf-8") as handle:
            for index, raw in enumerate(handle, start=1):
                payload = raw[:-1] if raw.endswith("\n") else raw
                if not payload.strip():
                    continue
                try:
                    entry = ControlPlaneAuditEntry.model_validate_json(payload)
                except Exception as exc:
                    return (False, count, f"line {index}: invalid entry ({exc})")
                if entry.previous_hash != previous:
                    return (False, count, f"line {index}: chain break")
                expected_hash = hashlib.sha256(
                    json.dumps(entry.data, sort_keys=True).encode("utf-8")
                ).hexdigest()
                if expected_hash != entry.data_hash:
                    return (False, count, f"line {index}: data hash mismatch")
                previous = hashlib.sha256(payload.encode("utf-8")).hexdigest()
                count += 1
        return (True, count, "")

    def query(
        self,
        *,
        event_type: str | None = None,
        session_id: str | None = None,
    ) -> list[dict[str, Any]]:
        if not self._path.exists():
            return []
        rows: list[dict[str, Any]] = []
        with self._path.open(encoding="utf-8") as handle:
            for raw in handle:
                text = raw.strip()
                if not text:
                    continue
                try:
                    entry = ControlPlaneAuditEntry.model_validate_json(text)
                except Exception:
                    continue
                if event_type and entry.event_type != event_type:
                    continue
                if session_id and entry.session_id != session_id:
                    continue
                rows.append(entry.model_dump(mode="json"))
        return rows

    def _resume(self) -> None:
        if not self._path.exists():
            return
        with self._path.open(encoding="utf-8") as handle:
            for raw in handle:
                payload = raw[:-1] if raw.endswith("\n") else raw
                if not payload.strip():
                    continue
                self._previous_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
                self._entry_count += 1
