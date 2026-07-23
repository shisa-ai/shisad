"""Service-owned pending-action record store and durable schema boundary."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

from shisad.core.approval import quarantine_state_file
from shisad.core.atomic_state import (
    AtomicWriteError,
    AtomicWriteFaultInjector,
    AtomicWriteStage,
    atomic_write_bytes,
)
from shisad.core.pending_action import (
    PENDING_ACTION_RECORD_SCHEMA_VERSION,
    PendingActionRecord,
)
from shisad.core.types import SessionId


class PendingActionStoreLoadStatus(StrEnum):
    MISSING = "missing"
    CURRENT = "current"
    LEGACY = "legacy"
    CORRUPT = "corrupt"
    UNSUPPORTED_SCHEMA = "unsupported_schema"


@dataclass(frozen=True, slots=True)
class PendingActionStoreLoadResult:
    status: PendingActionStoreLoadStatus
    payloads: tuple[dict[str, Any], ...] = ()
    reason: str = ""
    quarantined_path: Path | None = None


class PendingActionPayloadError(AtomicWriteError):
    """A current payload was rejected before atomic publication began."""

    def __init__(self, *, path: Path, reason: str) -> None:
        self.reason = reason
        super().__init__(
            path=path,
            stage=AtomicWriteStage.WRITE,
            publication_may_have_committed=False,
        )


class _RejectedPendingJSON(ValueError):
    pass


def _reject_nonfinite(value: str) -> None:
    raise _RejectedPendingJSON(f"non-finite JSON number: {value}")


def _reject_duplicate_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, member in pairs:
        if key in value:
            raise _RejectedPendingJSON(f"duplicate JSON member: {key}")
        value[key] = member
    return value


class PendingActionStore:
    """Own one daemon's pending records, session index, and durable path."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.actions: dict[str, PendingActionRecord] = {}
        self.by_session: dict[SessionId, list[str]] = {}

    def add(self, record: PendingActionRecord) -> None:
        confirmation_id = record.confirmation_id.strip()
        if not confirmation_id or confirmation_id != record.confirmation_id:
            raise ValueError("pending action confirmation ID is not canonical")
        if confirmation_id in self.actions:
            raise ValueError(f"duplicate pending action confirmation ID: {confirmation_id}")
        self.actions[confirmation_id] = record
        self.by_session.setdefault(record.session_id, []).append(confirmation_id)

    def remove(self, confirmation_id: str) -> PendingActionRecord | None:
        record = self.actions.pop(confirmation_id, None)
        if record is None:
            return None
        remaining = [
            candidate
            for candidate in self.by_session.get(record.session_id, ())
            if candidate != confirmation_id
        ]
        if remaining:
            self.by_session[record.session_id] = remaining
        else:
            self.by_session.pop(record.session_id, None)
        return record

    @staticmethod
    def assert_maps_index_parity(
        actions: Mapping[str, PendingActionRecord],
        by_session: Mapping[SessionId, Sequence[str]],
    ) -> None:
        expected: dict[SessionId, list[str]] = {}
        for confirmation_id, record in actions.items():
            if confirmation_id != record.confirmation_id or not confirmation_id.strip():
                raise ValueError("pending action map identity mismatch")
            expected.setdefault(record.session_id, []).append(confirmation_id)
        actual = {session_id: list(values) for session_id, values in by_session.items() if values}
        if actual != expected:
            raise ValueError("pending action session index mismatch")

    def assert_index_parity(self) -> None:
        self.assert_maps_index_parity(self.actions, self.by_session)

    def write_payloads(
        self,
        payloads: Sequence[Mapping[str, Any]],
        *,
        fault_injector: AtomicWriteFaultInjector | None = None,
    ) -> None:
        try:
            rows = [dict(payload) for payload in payloads]
        except (TypeError, ValueError) as exc:
            raise PendingActionPayloadError(path=self.path, reason=str(exc)) from exc
        status, reason = self._classify_rows(rows, allow_legacy=False)
        if status is not PendingActionStoreLoadStatus.CURRENT:
            raise PendingActionPayloadError(
                path=self.path,
                reason=reason or "pending action payload is not current",
            )
        try:
            encoded = json.dumps(rows, indent=2, allow_nan=False).encode("utf-8")
        except (TypeError, ValueError, UnicodeEncodeError) as exc:
            raise PendingActionPayloadError(path=self.path, reason=str(exc)) from exc
        atomic_write_bytes(
            self.path,
            encoded,
            fault_injector=fault_injector,
        )

    def load_payloads(self) -> PendingActionStoreLoadResult:
        try:
            raw = self.path.read_bytes()
        except FileNotFoundError:
            return PendingActionStoreLoadResult(status=PendingActionStoreLoadStatus.MISSING)
        except OSError as exc:
            return self.quarantine_unusable(
                PendingActionStoreLoadStatus.CORRUPT,
                f"pending state read failed: {exc}",
            )
        try:
            decoded = json.loads(
                raw.decode("utf-8"),
                object_pairs_hook=_reject_duplicate_members,
                parse_constant=_reject_nonfinite,
            )
        except (UnicodeDecodeError, json.JSONDecodeError, _RejectedPendingJSON) as exc:
            return self.quarantine_unusable(PendingActionStoreLoadStatus.CORRUPT, str(exc))
        if not isinstance(decoded, list) or not all(isinstance(row, dict) for row in decoded):
            return self.quarantine_unusable(
                PendingActionStoreLoadStatus.CORRUPT,
                "pending state must be a list of records",
            )
        rows = [dict(row) for row in decoded]
        status, reason = self._classify_rows(rows, allow_legacy=True)
        if status in {
            PendingActionStoreLoadStatus.CORRUPT,
            PendingActionStoreLoadStatus.UNSUPPORTED_SCHEMA,
        }:
            return self.quarantine_unusable(status, reason)
        return PendingActionStoreLoadResult(status=status, payloads=tuple(rows))

    def quarantine_unusable(
        self,
        status: PendingActionStoreLoadStatus,
        reason: str,
    ) -> PendingActionStoreLoadResult:
        if status not in {
            PendingActionStoreLoadStatus.CORRUPT,
            PendingActionStoreLoadStatus.UNSUPPORTED_SCHEMA,
        }:
            raise ValueError("only unusable pending state may be quarantined")
        quarantined = quarantine_state_file(self.path, label="pending_action")
        return PendingActionStoreLoadResult(
            status=status,
            reason=reason,
            quarantined_path=quarantined,
        )

    @staticmethod
    def _classify_rows(
        rows: Sequence[Mapping[str, Any]],
        *,
        allow_legacy: bool,
    ) -> tuple[PendingActionStoreLoadStatus, str]:
        legacy = False
        confirmation_ids: set[str] = set()
        for row in rows:
            schema_is_missing = "record_schema_version" not in row
            version = row.get("record_schema_version")
            if schema_is_missing:
                if not allow_legacy:
                    return (
                        PendingActionStoreLoadStatus.CORRUPT,
                        "pending action record schema is missing",
                    )
                legacy = True
            elif type(version) is not int or version < 1:
                return (
                    PendingActionStoreLoadStatus.CORRUPT,
                    "pending action record schema is invalid",
                )
            elif version > PENDING_ACTION_RECORD_SCHEMA_VERSION:
                return (
                    PendingActionStoreLoadStatus.UNSUPPORTED_SCHEMA,
                    f"unsupported pending action record schema: {version}",
                )
            elif version != PENDING_ACTION_RECORD_SCHEMA_VERSION:
                return (
                    PendingActionStoreLoadStatus.CORRUPT,
                    f"invalid pending action record schema: {version}",
                )

            confirmation_id = row.get("confirmation_id")
            if isinstance(confirmation_id, str) and confirmation_id.strip():
                if confirmation_id in confirmation_ids:
                    return (
                        PendingActionStoreLoadStatus.CORRUPT,
                        f"duplicate pending action confirmation ID: {confirmation_id}",
                    )
                confirmation_ids.add(confirmation_id)
            if schema_is_missing:
                continue
            session_id = row.get("session_id")
            identity = row.get("identity")
            if (
                not isinstance(confirmation_id, str)
                or confirmation_id != confirmation_id.strip()
                or not confirmation_id
                or not isinstance(session_id, str)
                or session_id != session_id.strip()
                or not session_id
                or not isinstance(identity, Mapping)
                or identity.get("confirmation_id") != confirmation_id
                or identity.get("session_id") != session_id
            ):
                return (
                    PendingActionStoreLoadStatus.CORRUPT,
                    "pending action current-record identity mismatch",
                )
        return (
            PendingActionStoreLoadStatus.LEGACY if legacy else PendingActionStoreLoadStatus.CURRENT,
            "",
        )
