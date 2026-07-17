"""Session action-history store for control-plane voters."""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

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
from shisad.security.control_plane.schema import ActionKind, ControlPlaneAction, Origin

logger = logging.getLogger(__name__)


def execution_action_surface_hash(action: ControlPlaneAction) -> str:
    """Bind replay accounting to stable action metadata, excluding runtime actor."""

    origin = action.origin
    payload = {
        "origin": {
            "session_id": origin.session_id,
            "user_id": origin.user_id,
            "workspace_id": origin.workspace_id,
            "task_id": origin.task_id,
            "skill_name": origin.skill_name,
            "channel": origin.channel,
            "trust_level": origin.trust_level,
        },
        "tool_name": action.tool_name,
        "action_kind": action.action_kind.value,
        "risk_tier": action.risk_tier.value,
        "resource_id": action.resource_id,
        "resource_ids": list(action.resource_ids),
        "network_hosts": list(action.network_hosts),
    }
    encoded = json.dumps(
        payload,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


class ActionHistoryRecord(BaseModel, frozen=True):
    """Append-only metadata record used by control-plane analyzers."""

    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    session_id: str
    origin: Origin = Field(default_factory=Origin)
    action_kind: ActionKind
    resource_id: str = ""
    tool_name: str
    observation_kind: Literal["action", "denied_action"] = "action"
    decision_status: Literal["", "allow", "block", "require_confirmation", "deny"] = ""
    execution_status: Literal["", "success", "failed", "outcome_unknown"] = ""
    reason_code: str = ""
    source: str = ""
    idempotency_key: str = ""
    trace_plan_hash: str = ""
    execution_action_surface_hash: str = ""


class SessionActionHistoryStore:
    """Per-session append-only history with last-N/window query primitives."""

    def __init__(self, storage_path: Path | None = None) -> None:
        self._storage_path = storage_path
        self._records: dict[str, list[ActionHistoryRecord]] = {}
        self._idempotent_records: dict[str, ActionHistoryRecord] = {}
        self._state_load_result = StateLoadResult(
            StateLoadStatus.OK if storage_path is None else StateLoadStatus.MISSING
        )
        self._persistence_degradation: AtomicWriteError | DurableAppendError | None = None
        self._state_fault_injector: DurableAppendFaultInjector | None = None
        self._load()

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
            "problems": ["control_plane_history_state_degraded"] if self.state_degraded else [],
            "path": str(self._storage_path or ""),
            "load_status": load_result.status.value,
            "reason": load_result.reason,
            "schema_version": load_result.schema_version,
            "legacy": load_result.legacy,
            "fail_closed": self.state_degraded,
            "stage": persistence.stage.value if persistence is not None else "",
            "remediation": (
                "Restore or explicitly reset the retained control-plane history, then restart "
                "shisad."
                if self.state_degraded
                else ""
            ),
        }

    def reset_state(self) -> int:
        """Durably publish an empty history and clear its typed degradation."""

        cleared = sum(len(records) for records in self._records.values())
        if self._storage_path is not None:
            try:
                atomic_write_bytes(self._storage_path, b"")
            except AtomicWriteError as exc:
                self._persistence_degradation = exc
                raise
        self._records.clear()
        self._idempotent_records.clear()
        self._persistence_degradation = None
        self._state_load_result = StateLoadResult(StateLoadStatus.OK)
        return cleared

    def _require_available(self, *, transition: str) -> None:
        if not self.state_degraded:
            return
        persistence = self._persistence_degradation
        raise StatePersistenceDegradedError(
            authority="control_plane_history",
            transition=transition,
            stage=persistence.stage.value if persistence is not None else "load",
            reason=(
                "publication_commit_uncertain"
                if persistence is not None
                else self._state_load_result.reason or self._state_load_result.status.value
            ),
        )

    def append(self, record: ActionHistoryRecord) -> bool:
        idempotency_key = record.idempotency_key.strip()
        if idempotency_key:
            existing = self._idempotent_records.get(idempotency_key)
            if existing is not None:
                if existing != record:
                    raise ValueError("control_plane_history_idempotency_conflict")
                return False
        self._require_available(transition="append")
        session_id = record.session_id
        if self._storage_path is None:
            self._records.setdefault(session_id, []).append(record)
            if idempotency_key:
                self._idempotent_records[idempotency_key] = record
            return True
        try:
            durable_append_bytes(
                self._storage_path,
                (record.model_dump_json() + "\n").encode("utf-8"),
                fault_injector=self._state_fault_injector,
            )
        except DurableAppendError as exc:
            if exc.publication_may_have_committed:
                self._persistence_degradation = exc
            raise
        self._records.setdefault(session_id, []).append(record)
        if idempotency_key:
            self._idempotent_records[idempotency_key] = record
        self._state_load_result = StateLoadResult(StateLoadStatus.OK)
        return True

    def append_action(
        self,
        action: ControlPlaneAction,
        *,
        decision_status: str = "",
        execution_status: str = "",
        observation_kind: str = "action",
        reason_code: str = "",
        source: str = "",
        idempotency_key: str = "",
        trace_plan_hash: str = "",
    ) -> bool:
        record = ActionHistoryRecord(
            timestamp=action.timestamp,
            session_id=action.origin.session_id,
            origin=action.origin,
            action_kind=action.action_kind,
            resource_id=action.resource_id,
            tool_name=action.tool_name,
            observation_kind=observation_kind,
            decision_status=decision_status,
            execution_status=execution_status,
            reason_code=reason_code,
            source=source,
            idempotency_key=idempotency_key.strip(),
            trace_plan_hash=trace_plan_hash.strip(),
            execution_action_surface_hash=(
                execution_action_surface_hash(action) if execution_status else ""
            ),
        )
        return self.append(record)

    def idempotent_record(self, idempotency_key: str) -> ActionHistoryRecord | None:
        normalized_key = idempotency_key.strip()
        if not normalized_key:
            return None
        return self._idempotent_records.get(normalized_key)

    def append_denied_action(
        self,
        action: ControlPlaneAction,
        *,
        reason_code: str,
        source: str,
        timestamp: datetime | None = None,
    ) -> ActionHistoryRecord:
        record = ActionHistoryRecord(
            timestamp=timestamp or datetime.now(UTC),
            session_id=action.origin.session_id,
            origin=action.origin,
            action_kind=action.action_kind,
            resource_id=action.resource_id,
            tool_name=action.tool_name,
            observation_kind="denied_action",
            decision_status="deny",
            reason_code=reason_code,
            source=source,
        )
        self.append(record)
        return record

    def last_n(self, session_id: str, n: int) -> list[ActionHistoryRecord]:
        if n <= 0:
            return []
        records = self._records.get(session_id, [])
        if n >= len(records):
            return list(records)
        return list(records[-n:])

    def in_window(
        self,
        session_id: str,
        seconds: int,
        *,
        now: datetime | None = None,
    ) -> list[ActionHistoryRecord]:
        if seconds <= 0:
            return []
        current = now or datetime.now(UTC)
        start = current - timedelta(seconds=seconds)
        records = self._records.get(session_id, [])
        return [item for item in records if item.timestamp >= start]

    def all_for_session(self, session_id: str) -> list[ActionHistoryRecord]:
        return list(self._records.get(session_id, []))

    def for_analysis(
        self,
        session_id: str,
        *,
        window_seconds: int | None = None,
        last_n: int | None = None,
        now: datetime | None = None,
        observation_kinds: set[str] | None = None,
    ) -> list[ActionHistoryRecord]:
        rows: list[ActionHistoryRecord]
        if window_seconds is not None:
            rows = self.in_window(session_id, window_seconds, now=now)
        elif last_n is not None:
            rows = self.last_n(session_id, last_n)
        else:
            rows = self.all_for_session(session_id)
        if observation_kinds is not None:
            rows = [row for row in rows if row.observation_kind in observation_kinds]
        return self.dedupe_for_analysis(rows)

    @classmethod
    def dedupe_for_analysis(cls, rows: list[ActionHistoryRecord]) -> list[ActionHistoryRecord]:
        deduped: list[ActionHistoryRecord] = []
        seen: set[tuple[str, str, str, str, str, str]] = set()
        for row in rows:
            key = cls.analysis_key(row)
            if key in seen:
                continue
            seen.add(key)
            deduped.append(row)
        return deduped

    @staticmethod
    def analysis_key(record: ActionHistoryRecord) -> tuple[str, str, str, str, str, str]:
        return (
            record.timestamp.isoformat(),
            record.action_kind.value,
            record.resource_id,
            record.tool_name,
            record.observation_kind,
            record.reason_code,
        )

    def _load(self) -> None:
        if self._storage_path is None:
            return
        try:
            raw_bytes = read_owner_only_regular_file(self._storage_path)
        except OSError:
            self._state_load_result = StateLoadResult(
                StateLoadStatus.CORRUPT,
                reason="history_read_failed",
            )
            return
        if raw_bytes is None:
            return
        if raw_bytes and not raw_bytes.endswith(b"\n"):
            self._state_load_result = StateLoadResult(
                StateLoadStatus.CORRUPT,
                reason="history_unterminated_row",
            )
            logger.warning("control-plane history: retained unterminated final record")
            return
        candidate_records: dict[str, list[ActionHistoryRecord]] = {}
        candidate_idempotent: dict[str, ActionHistoryRecord] = {}
        try:
            lines = raw_bytes.decode("utf-8").splitlines()
        except UnicodeError:
            self._state_load_result = StateLoadResult(
                StateLoadStatus.CORRUPT,
                reason="history_invalid_encoding",
            )
            return
        for line_number, line in enumerate(lines, start=1):
            text = line.strip()
            if not text:
                continue
            try:
                record = ActionHistoryRecord.model_validate_json(text)
            except ValidationError:
                logger.warning(
                    "control-plane history: retained malformed record line %s",
                    line_number,
                )
                self._state_load_result = StateLoadResult(
                    StateLoadStatus.CORRUPT,
                    reason=f"invalid_history_record:{line_number}",
                )
                return
            idempotency_key = record.idempotency_key.strip()
            if idempotency_key:
                existing = candidate_idempotent.get(idempotency_key)
                if existing is not None and existing != record:
                    self._state_load_result = StateLoadResult(
                        StateLoadStatus.CORRUPT,
                        reason="history_idempotency_conflict",
                    )
                    return
                candidate_idempotent[idempotency_key] = record
            candidate_records.setdefault(record.session_id, []).append(record)
        self._records = candidate_records
        self._idempotent_records = candidate_idempotent
        self._state_load_result = StateLoadResult(StateLoadStatus.OK)

    def dump_json(self) -> str:
        payload = {
            session_id: [record.model_dump(mode="json") for record in records]
            for session_id, records in self._records.items()
        }
        return json.dumps(payload, sort_keys=True)
