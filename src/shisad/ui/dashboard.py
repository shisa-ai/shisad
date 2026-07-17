"""Security dashboard helpers backed by audit-log queries."""

from __future__ import annotations

import json
import stat
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from shisad.core.atomic_state import (
    AtomicWriteError,
    AtomicWriteFaultInjector,
    StateLoadResult,
    StateLoadStatus,
    StatePersistenceDegradedError,
    atomic_write_bytes,
    decode_versioned_json_snapshot,
    encode_versioned_json_snapshot,
    read_owned_regular_file,
)
from shisad.core.audit import AuditLog

ALERT_EVENT_TYPES = {
    "AnomalyReported",
    "LockdownChanged",
    "PlanViolationDetected",
    "SandboxEscapeDetected",
    "OutputFirewallAlert",
}

SKILL_PROVENANCE_EVENT_TYPES = {
    "SkillReviewRequested",
    "SkillInstalled",
    "SkillProfiled",
    "SkillRevoked",
    "SkillToolRegistrationDropped",
}

_DASHBOARD_MARKS_VERSION = 1


def _as_datetime(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed


def _json_text(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, ensure_ascii=True)


@dataclass(slots=True)
class DashboardQuery:
    """Filter options for dashboard audit explorer."""

    since: datetime | None = None
    event_type: str | None = None
    session_id: str | None = None
    actor: str | None = None
    text_search: str = ""
    limit: int = 100


class SecurityDashboard:
    """Read-only dashboard over append-only audit stream."""

    def __init__(self, *, audit_log: AuditLog, marks_path: Path | None = None) -> None:
        self._audit_log = audit_log
        self._marks_path = marks_path
        self._marks: dict[str, str] = {}
        self._state_load_result = StateLoadResult(StateLoadStatus.MISSING)
        self._persistence_degradation: AtomicWriteError | None = None
        self._state_fault_injector: AtomicWriteFaultInjector | None = None
        if marks_path is not None:
            self._load_marks()

    def audit_explorer(self, query: DashboardQuery) -> dict[str, Any]:
        rows = self._audit_log.query(
            since=query.since,
            event_type=query.event_type,
            session_id=query.session_id,
            actor=query.actor,
            limit=max(1, query.limit),
        )
        if query.text_search.strip():
            needle = query.text_search.strip().lower()
            rows = [
                row
                for row in rows
                if needle
                in _json_text(
                    {
                        "event_type": row.get("event_type", ""),
                        "action": row.get("action", ""),
                        "target": row.get("target", ""),
                        "decision": row.get("decision", ""),
                        "reasoning": row.get("reasoning", ""),
                    }
                ).lower()
            ]
        return {"events": rows, "total": len(rows)}

    def blocked_or_flagged_egress(self, *, limit: int = 200) -> dict[str, Any]:
        proxy_rows = self._audit_log.query(event_type="ProxyRequestEvaluated", limit=limit)
        cp_rows = self._audit_log.query(event_type="ControlPlaneNetworkObserved", limit=limit)
        rows: list[dict[str, Any]] = []
        for row in [*proxy_rows, *cp_rows]:
            data = row.get("data", {})
            allowed = bool(data.get("allowed", False))
            reason = str(data.get("reason", "")).lower()
            if not allowed or "flag" in reason or "anomaly" in reason:
                rows.append(row)
        rows.sort(
            key=lambda row: _as_datetime(str(row.get("timestamp", "1970-01-01T00:00:00+00:00"))),
            reverse=True,
        )
        return {"events": rows[:limit], "total": len(rows)}

    def skill_provenance(self, *, limit: int = 200) -> dict[str, Any]:
        rows: list[dict[str, Any]] = []
        for event_type in sorted(SKILL_PROVENANCE_EVENT_TYPES):
            rows.extend(
                self._audit_log.query(
                    event_type=event_type,
                    limit=limit,
                    tail=True,
                )
            )
        result = sorted(
            rows,
            key=lambda row: _as_datetime(str(row.get("timestamp", "1970-01-01T00:00:00+00:00"))),
            reverse=True,
        )
        return {"events": result[:limit], "total": len(result)}

    def alerts(self, *, limit: int = 200) -> dict[str, Any]:
        rows: list[dict[str, Any]] = []
        for event_type in sorted(ALERT_EVENT_TYPES):
            rows.extend(self._audit_log.query(event_type=event_type, limit=limit))
        rows.sort(
            key=lambda row: _as_datetime(str(row.get("timestamp", "1970-01-01T00:00:00+00:00"))),
            reverse=True,
        )
        output: list[dict[str, Any]] = []
        for row in rows[:limit]:
            event_id = str(row.get("event_id", ""))
            marked = self._marks.get(event_id, "")
            row_copy = dict(row)
            row_copy["acknowledged_reason"] = marked
            output.append(row_copy)
        return {"alerts": output, "total": len(output)}

    def mark_false_positive(self, *, event_id: str, reason: str) -> None:
        if not self._marks_path:
            return
        normalized = event_id.strip()
        if not normalized:
            return
        self._require_marks_available(transition="mark_false_positive")
        candidate = dict(self._marks)
        candidate[normalized] = reason.strip() or "false_positive"
        self._persist_marks(candidate)
        self._marks = candidate

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
        load_result = self._state_load_result
        persistence = self._persistence_degradation
        problems: list[str] = []
        if persistence is not None:
            problems.append("dashboard_marks_persistence_degraded")
        elif load_result.status in {
            StateLoadStatus.CORRUPT,
            StateLoadStatus.UNSUPPORTED_SCHEMA,
        }:
            problems.append(f"dashboard_marks_{load_result.status.value}")
        return {
            "status": "degraded" if self.state_degraded else "ok",
            "problems": problems,
            "path": str(self._marks_path or ""),
            "load_status": load_result.status.value,
            "reason": load_result.reason,
            "schema_version": load_result.schema_version,
            "legacy": load_result.legacy,
            "fail_closed": self.state_degraded,
            "stage": persistence.stage.value if persistence is not None else "",
            "remediation": (
                "Restore dashboard false-positive marks from a trusted backup or explicitly "
                "reset the retained marks file after verification, then restart shisad."
                if self.state_degraded
                else ""
            ),
        }

    def reset_state(self) -> int:
        """Durably clear false-positive marks and all rollback/load metadata."""

        mark_count = len(self._marks)
        if self._marks_path is None:
            self._marks = {}
            self._state_load_result = StateLoadResult(StateLoadStatus.MISSING)
            self._persistence_degradation = None
            return mark_count
        try:
            atomic_write_bytes(
                self._marks_path,
                encode_versioned_json_snapshot({}, version=_DASHBOARD_MARKS_VERSION),
                fault_injector=self._state_fault_injector,
            )
        except AtomicWriteError as exc:
            self._persistence_degradation = exc
            raise
        self._marks = {}
        self._state_load_result = StateLoadResult(
            StateLoadStatus.OK,
            schema_version=_DASHBOARD_MARKS_VERSION,
        )
        self._persistence_degradation = None
        return mark_count

    def _load_marks(self) -> None:
        if self._marks_path is None:
            return
        try:
            target_stat = self._marks_path.lstat()
        except FileNotFoundError:
            self._state_load_result = StateLoadResult(StateLoadStatus.MISSING)
            return
        except OSError:
            self._state_load_result = StateLoadResult(
                StateLoadStatus.CORRUPT,
                reason="marks_stat_failed",
            )
            return
        if not stat.S_ISREG(target_stat.st_mode):
            self._state_load_result = StateLoadResult(
                StateLoadStatus.CORRUPT,
                reason="invalid_marks_target",
            )
            return
        try:
            raw_bytes = read_owned_regular_file(self._marks_path)
        except OSError:
            self._state_load_result = StateLoadResult(
                StateLoadStatus.CORRUPT,
                reason="marks_read_failed",
            )
            return
        if raw_bytes is None:
            self._state_load_result = StateLoadResult(
                StateLoadStatus.CORRUPT,
                reason="marks_read_failed",
            )
            return
        try:
            raw_payload = json.loads(raw_bytes.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError, RecursionError):
            raw_payload = None
        legacy_candidate = isinstance(raw_payload, dict) and all(
            isinstance(key, str)
            and bool(key.strip())
            and isinstance(value, str)
            and bool(value.strip())
            for key, value in raw_payload.items()
        )
        if legacy_candidate:
            load_result = StateLoadResult(StateLoadStatus.OK, legacy=True)
            payload: Any = raw_payload
        else:
            load_result, payload = decode_versioned_json_snapshot(
                raw_bytes,
                supported_version=_DASHBOARD_MARKS_VERSION,
            )
            if load_result.status is not StateLoadStatus.OK:
                self._state_load_result = load_result
                return
        if not isinstance(payload, dict) or any(
            not isinstance(key, str)
            or not key.strip()
            or not isinstance(value, str)
            or not value.strip()
            for key, value in payload.items()
        ):
            self._state_load_result = StateLoadResult(
                StateLoadStatus.CORRUPT,
                reason="invalid_marks_payload",
                schema_version=load_result.schema_version,
                legacy=load_result.legacy,
            )
            return
        self._marks = dict(payload)
        self._state_load_result = load_result

    def _persist_marks(self, marks: dict[str, str]) -> None:
        if self._marks_path is None:
            return
        try:
            atomic_write_bytes(
                self._marks_path,
                encode_versioned_json_snapshot(marks, version=_DASHBOARD_MARKS_VERSION),
                fault_injector=self._state_fault_injector,
            )
        except AtomicWriteError as exc:
            if exc.publication_may_have_committed:
                self._persistence_degradation = exc
            raise
        self._state_load_result = StateLoadResult(
            StateLoadStatus.OK,
            schema_version=_DASHBOARD_MARKS_VERSION,
        )

    def _require_marks_available(self, *, transition: str) -> None:
        persistence = self._persistence_degradation
        if persistence is not None:
            raise StatePersistenceDegradedError(
                authority="dashboard_marks",
                transition=transition,
                stage=persistence.stage.value,
                reason=(
                    "commit_uncertain"
                    if persistence.publication_may_have_committed
                    else "publication_failed"
                ),
            )
        load_result = self._state_load_result
        if load_result.status in {
            StateLoadStatus.CORRUPT,
            StateLoadStatus.UNSUPPORTED_SCHEMA,
        }:
            raise StatePersistenceDegradedError(
                authority="dashboard_marks",
                transition=transition,
                stage="load",
                reason=load_result.reason or load_result.status.value,
            )
