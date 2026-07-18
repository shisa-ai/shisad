"""Session action-history store for control-plane voters."""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import UTC, datetime, timedelta
from pathlib import Path

from pydantic import BaseModel, Field, ValidationError

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
    observation_kind: str = "action"
    decision_status: str = ""
    execution_status: str = ""
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
        self._load()

    def append(self, record: ActionHistoryRecord) -> bool:
        idempotency_key = record.idempotency_key.strip()
        if idempotency_key:
            existing = self._idempotent_records.get(idempotency_key)
            if existing is not None:
                if existing != record:
                    raise ValueError("control_plane_history_idempotency_conflict")
                return False
        session_id = record.session_id
        self._records.setdefault(session_id, []).append(record)
        if self._storage_path is None:
            if idempotency_key:
                self._idempotent_records[idempotency_key] = record
            return True
        self._storage_path.parent.mkdir(parents=True, exist_ok=True)
        with self._storage_path.open("a", encoding="utf-8") as handle:
            handle.write(record.model_dump_json() + "\n")
        if idempotency_key:
            self._idempotent_records[idempotency_key] = record
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
        if self._storage_path is None or not self._storage_path.exists():
            return
        with self._storage_path.open(encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                text = line.strip()
                if not text:
                    continue
                try:
                    record = ActionHistoryRecord.model_validate_json(text)
                except ValidationError:
                    logger.warning(
                        "control-plane history: skipping malformed record line %s",
                        line_number,
                    )
                    continue
                idempotency_key = record.idempotency_key.strip()
                if idempotency_key:
                    existing = self._idempotent_records.get(idempotency_key)
                    if existing is not None and existing != record:
                        raise ValueError("control_plane_history_idempotency_conflict")
                    self._idempotent_records[idempotency_key] = record
                self._records.setdefault(record.session_id, []).append(record)

    def dump_json(self) -> str:
        payload = {
            session_id: [record.model_dump(mode="json") for record in records]
            for session_id, records in self._records.items()
        }
        return json.dumps(payload, sort_keys=True)
