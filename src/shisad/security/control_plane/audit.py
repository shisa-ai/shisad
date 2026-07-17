"""Separate control-plane audit stream with independent hash chain."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, ValidationError

from shisad.core.atomic_state import (
    AtomicWriteError,
    DurableAppendError,
    DurableAppendFaultInjector,
    StateLoadResult,
    StateLoadStatus,
    StatePersistenceDegradedError,
    atomic_write_bytes,
    durable_append_bytes,
    read_owner_only_regular_file,
)
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
        self._state_load_result = StateLoadResult(StateLoadStatus.MISSING)
        self._persistence_degradation: AtomicWriteError | DurableAppendError | None = None
        self._state_fault_injector: DurableAppendFaultInjector | None = None
        self._resume()

    @property
    def state_load_result(self) -> StateLoadResult:
        return self._state_load_result

    @property
    def state_degraded(self) -> bool:
        return self._persistence_degradation is not None or self._state_load_result.status in {
            StateLoadStatus.CORRUPT,
            StateLoadStatus.UNSUPPORTED_SCHEMA,
        }

    def state_status(self) -> dict[str, Any]:
        persistence = self._persistence_degradation
        load_result = self._state_load_result
        return {
            "status": "degraded" if self.state_degraded else "ok",
            "problems": ["control_plane_audit_state_degraded"] if self.state_degraded else [],
            "path": str(self._path),
            "load_status": load_result.status.value,
            "reason": load_result.reason,
            "schema_version": load_result.schema_version,
            "legacy": load_result.legacy,
            "fail_closed": self.state_degraded,
            "stage": persistence.stage.value if persistence is not None else "",
            "remediation": (
                "Restore or explicitly reset the retained control-plane audit chain, then "
                "restart shisad."
                if self.state_degraded
                else ""
            ),
        }

    def reset_state(self) -> int:
        """Durably publish an empty audit chain and reset its genesis cursor."""

        cleared = self._entry_count
        try:
            atomic_write_bytes(self._path, b"")
        except AtomicWriteError as exc:
            self._persistence_degradation = exc
            raise
        self._previous_hash = _GENESIS_HASH
        self._entry_count = 0
        self._persistence_degradation = None
        self._state_load_result = StateLoadResult(StateLoadStatus.OK)
        return cleared

    def _require_available(self, *, transition: str) -> None:
        if not self.state_degraded:
            return
        persistence = self._persistence_degradation
        raise StatePersistenceDegradedError(
            authority="control_plane_audit",
            transition=transition,
            stage=persistence.stage.value if persistence is not None else "load",
            reason=(
                "publication_commit_uncertain"
                if persistence is not None
                else self._state_load_result.reason or self._state_load_result.status.value
            ),
        )

    @property
    def entry_count(self) -> int:
        return self._entry_count

    @property
    def path(self) -> Path:
        return self._path

    def append(self, *, event_type: str, session_id: str, actor: str, data: dict[str, Any]) -> None:
        self._require_available(transition="append")
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
        try:
            durable_append_bytes(
                self._path,
                (payload + "\n").encode("utf-8"),
                fault_injector=self._state_fault_injector,
            )
        except DurableAppendError as exc:
            if exc.publication_may_have_committed:
                self._persistence_degradation = exc
            raise
        self._previous_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        self._entry_count += 1
        self._state_load_result = StateLoadResult(StateLoadStatus.OK)

    def verify_chain(self) -> tuple[bool, int, str]:
        try:
            raw_bytes = read_owner_only_regular_file(self._path)
        except OSError as exc:
            return (False, 0, f"read failed ({exc})")
        if raw_bytes is None:
            return (True, 0, "")
        return self._verify_chain_bytes(raw_bytes)

    @staticmethod
    def _verify_chain_bytes(raw_bytes: bytes) -> tuple[bool, int, str]:
        try:
            text = raw_bytes.decode("utf-8")
        except UnicodeError as exc:
            return (False, 0, f"invalid encoding ({exc})")
        previous = _GENESIS_HASH
        count = 0
        for index, raw in enumerate(text.splitlines(keepends=True), start=1):
            payload = raw[:-1] if raw.endswith("\n") else raw
            if payload.endswith("\r"):
                payload = payload[:-1]
            if not payload.strip():
                continue
            try:
                entry = ControlPlaneAuditEntry.model_validate_json(payload)
            except ValidationError as exc:
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
        if self.state_degraded:
            return []
        try:
            raw_bytes = read_owner_only_regular_file(self._path)
        except OSError:
            return []
        if raw_bytes is None:
            return []
        rows: list[dict[str, Any]] = []
        for raw in raw_bytes.splitlines():
            text = raw.strip()
            if not text:
                continue
            try:
                entry = ControlPlaneAuditEntry.model_validate_json(text)
            except ValidationError:
                continue
            if event_type and entry.event_type != event_type:
                continue
            if session_id and entry.session_id != session_id:
                continue
            rows.append(entry.model_dump(mode="json"))
        return rows

    def _resume(self) -> None:
        try:
            raw_bytes = read_owner_only_regular_file(self._path)
        except OSError:
            self._state_load_result = StateLoadResult(
                StateLoadStatus.CORRUPT,
                reason="audit_read_failed",
            )
            return
        if raw_bytes is None:
            return
        if raw_bytes and not raw_bytes.endswith(b"\n"):
            self._state_load_result = StateLoadResult(
                StateLoadStatus.CORRUPT,
                reason="audit_unterminated_row",
            )
            return
        ok, count, error = self._verify_chain_bytes(raw_bytes)
        if not ok:
            self._state_load_result = StateLoadResult(
                StateLoadStatus.CORRUPT,
                reason=error,
            )
            return
        previous = _GENESIS_HASH
        for raw in raw_bytes.decode("utf-8").splitlines():
            payload = raw[:-1] if raw.endswith("\r") else raw
            if not payload.strip():
                continue
            previous = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        self._previous_hash = previous
        self._entry_count = count
        self._state_load_result = StateLoadResult(StateLoadStatus.OK)
