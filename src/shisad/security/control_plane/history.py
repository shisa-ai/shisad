"""Session action-history store for control-plane voters."""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime, timedelta
from pathlib import Path

from pydantic import BaseModel, Field, ValidationError

from shisad.security.control_plane.schema import ActionKind, ControlPlaneAction, Origin

logger = logging.getLogger(__name__)


class ActionHistoryRecord(BaseModel, frozen=True):
    """Append-only metadata record used by control-plane analyzers."""

    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    session_id: str
    origin: Origin = Field(default_factory=Origin)
    action_kind: ActionKind
    resource_id: str = ""
    tool_name: str
    decision_status: str = ""
    execution_status: str = ""


class SessionActionHistoryStore:
    """Per-session append-only history with last-N/window query primitives."""

    def __init__(self, storage_path: Path | None = None) -> None:
        self._storage_path = storage_path
        self._records: dict[str, list[ActionHistoryRecord]] = {}
        self._load()

    def append(self, record: ActionHistoryRecord) -> None:
        session_id = record.session_id
        self._records.setdefault(session_id, []).append(record)
        if self._storage_path is None:
            return
        self._storage_path.parent.mkdir(parents=True, exist_ok=True)
        with self._storage_path.open("a", encoding="utf-8") as handle:
            handle.write(record.model_dump_json() + "\n")

    def append_action(
        self,
        action: ControlPlaneAction,
        *,
        decision_status: str = "",
        execution_status: str = "",
    ) -> ActionHistoryRecord:
        record = ActionHistoryRecord(
            timestamp=action.timestamp,
            session_id=action.origin.session_id,
            origin=action.origin,
            action_kind=action.action_kind,
            resource_id=action.resource_id,
            tool_name=action.tool_name,
            decision_status=decision_status,
            execution_status=execution_status,
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
    ) -> list[ActionHistoryRecord]:
        rows: list[ActionHistoryRecord]
        if window_seconds is not None:
            rows = self.in_window(session_id, window_seconds, now=now)
        elif last_n is not None:
            rows = self.last_n(session_id, last_n)
        else:
            rows = self.all_for_session(session_id)
        return self.dedupe_for_analysis(rows)

    @classmethod
    def dedupe_for_analysis(cls, rows: list[ActionHistoryRecord]) -> list[ActionHistoryRecord]:
        deduped: list[ActionHistoryRecord] = []
        seen: set[tuple[str, str, str, str]] = set()
        for row in rows:
            key = cls._analysis_key(row)
            if key in seen:
                continue
            seen.add(key)
            deduped.append(row)
        return deduped

    @staticmethod
    def _analysis_key(record: ActionHistoryRecord) -> tuple[str, str, str, str]:
        return (
            record.timestamp.isoformat(),
            record.action_kind.value,
            record.resource_id,
            record.tool_name,
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
                self._records.setdefault(record.session_id, []).append(record)

    def dump_json(self) -> str:
        payload = {
            session_id: [record.model_dump(mode="json") for record in records]
            for session_id, records in self._records.items()
        }
        return json.dumps(payload, sort_keys=True)
