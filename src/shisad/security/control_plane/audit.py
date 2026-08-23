"""Separate control-plane audit stream with independent hash chain."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, ValidationError

from shisad.core.audit_segments import (
    AuditIntegrityError,
    AuditSegmentStore,
    AuditUnavailableError,
)
from shisad.security.control_plane.schema import sanitize_metadata_payload

_GENESIS_HASH = hashlib.sha256(b"shisad-control-plane-audit-genesis").hexdigest()
MAX_SEGMENT_BYTES = 32 * 1024 * 1024
MAX_ARCHIVES = 4


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

    def __init__(self, path: Path, *, _read_only: bool = False) -> None:
        self._path = path
        self._previous_hash = _GENESIS_HASH
        self._entry_count = 0
        self._segments = AuditSegmentStore(
            path,
            stream="control_plane",
            genesis_hash=_GENESIS_HASH,
            verify_row=self._verify_row,
            max_segment_bytes=MAX_SEGMENT_BYTES,
            max_archives=MAX_ARCHIVES,
            admit=not _read_only,
        )
        self._resume()

    @property
    def entry_count(self) -> int:
        return self._entry_count

    @property
    def path(self) -> Path:
        return self._path

    @property
    def lifecycle_status(self) -> dict[str, Any]:
        return self._segments.lifecycle_status

    def ensure_available(self) -> None:
        self._segments.ensure_available()

    def append(self, *, event_type: str, session_id: str, actor: str, data: dict[str, Any]) -> None:
        self._segments.ensure_available()
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
        terminal_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        try:
            self._segments.append(payload, terminal_hash)
        except AuditUnavailableError:
            raise
        except Exception:
            self._segments.mark_unavailable("audit.append_failed")
            raise
        self._previous_hash = terminal_hash
        self._entry_count += 1

    def verify_chain(self) -> tuple[bool, int, str]:
        try:
            verified = self._segments.verify()
        except (AuditIntegrityError, OSError, UnicodeError, ValueError) as exc:
            return (False, self._entry_count, str(exc))
        return (True, verified.entry_count, "")

    def query(
        self,
        *,
        event_type: str | None = None,
        session_id: str | None = None,
    ) -> list[dict[str, Any]]:
        valid, _count, error = self.verify_chain()
        if not valid:
            raise AuditIntegrityError(error)
        rows: list[dict[str, Any]] = []
        for text in self._segments.iter_rows():
            entry = ControlPlaneAuditEntry.model_validate_json(text)
            if event_type and entry.event_type != event_type:
                continue
            if session_id and entry.session_id != session_id:
                continue
            rows.append(entry.model_dump(mode="json"))
        return rows

    def _resume(self) -> None:
        verified = self._segments.verification
        self._entry_count = verified.entry_count
        self._previous_hash = (
            verified.segments[-1].terminal_hash if verified.segments else _GENESIS_HASH
        )

    @staticmethod
    def _verify_row(payload: str, previous_hash: str) -> str:
        try:
            entry = ControlPlaneAuditEntry.model_validate_json(payload)
        except ValidationError as exc:
            raise AuditIntegrityError("invalid entry") from exc
        if entry.previous_hash != previous_hash:
            raise AuditIntegrityError("chain break")
        expected_hash = hashlib.sha256(
            json.dumps(entry.data, sort_keys=True).encode("utf-8")
        ).hexdigest()
        if expected_hash != entry.data_hash:
            raise AuditIntegrityError("data hash mismatch")
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()
