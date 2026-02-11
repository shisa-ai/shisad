"""Security dashboard helpers backed by audit-log queries."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from shisad.core.audit import AuditLog

ALERT_EVENT_TYPES = {
    "AnomalyReported",
    "LockdownChanged",
    "PlanViolationDetected",
    "SandboxEscapeDetected",
    "OutputFirewallAlert",
}


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
                if needle in _json_text(
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
            key=lambda row: _as_datetime(
                str(row.get("timestamp", "1970-01-01T00:00:00+00:00"))
            ),
            reverse=True,
        )
        return {"events": rows[:limit], "total": len(rows)}

    def skill_provenance(self, *, limit: int = 200) -> dict[str, Any]:
        rows = self._audit_log.query(limit=limit)
        wanted_event_types = {
            "SkillReviewRequested",
            "SkillInstalled",
            "SkillProfiled",
            "SkillRevoked",
        }
        result = [
            row
            for row in rows
            if str(row.get("event_type", "")) in wanted_event_types
        ]
        return {"events": result, "total": len(result)}

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
        self._marks[normalized] = reason.strip() or "false_positive"
        self._persist_marks()

    def _load_marks(self) -> None:
        if self._marks_path is None or not self._marks_path.exists():
            return
        try:
            payload = json.loads(self._marks_path.read_text(encoding="utf-8"))
        except Exception:
            return
        if isinstance(payload, dict):
            self._marks = {str(key): str(value) for key, value in payload.items()}

    def _persist_marks(self) -> None:
        if self._marks_path is None:
            return
        self._marks_path.parent.mkdir(parents=True, exist_ok=True)
        self._marks_path.write_text(
            json.dumps(self._marks, indent=2, sort_keys=True),
            encoding="utf-8",
        )
