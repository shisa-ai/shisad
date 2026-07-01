"""Structured plan-step state for UI work-breakdown surfaces."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from threading import RLock
from typing import Any

from shisad.core.types import SessionId

PLAN_STEP_STATUSES: frozenset[str] = frozenset(
    {"pending", "in_progress", "blocked", "done", "failed"}
)
PLAN_STEP_TERMINAL_STATUSES: frozenset[str] = frozenset({"done", "failed"})
PLAN_STEP_CURRENT_STATUSES: frozenset[str] = frozenset({"in_progress", "blocked"})


def normalize_plan_step_status(value: object) -> str:
    status = str(value or "").strip().lower()
    if status in PLAN_STEP_STATUSES:
        return status
    return "unknown"


def _safe_display_text(value: object, *, fallback: str = "", limit: int = 120) -> str:
    text = str(value or "").strip()
    cleaned = "".join(char if ord(char) >= 32 and ord(char) != 127 else " " for char in text)
    normalized = " ".join(cleaned.split())
    if not normalized:
        normalized = fallback
    if limit > 0 and len(normalized) > limit:
        return normalized[: limit - 1].rstrip() + "..."
    return normalized


class PlanStepStore:
    """In-memory structured plan-step state keyed by session."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._steps_by_session: dict[str, list[dict[str, Any]]] = {}

    def start_plan_step(
        self,
        *,
        session_id: SessionId,
        plan_hash: str,
        title: str = "Current request",
    ) -> str:
        normalized_session = str(session_id).strip()
        normalized_plan = _safe_display_text(plan_hash, fallback="plan", limit=80)
        step_id = f"{normalized_plan}:1"
        self.replace_steps(
            session_id=session_id,
            steps=[
                {
                    "id": step_id,
                    "session_id": normalized_session,
                    "plan_hash": normalized_plan,
                    "order": 1,
                    "title": title,
                    "status": "in_progress",
                    "current": True,
                }
            ],
        )
        return step_id

    def replace_steps(
        self,
        *,
        session_id: SessionId,
        steps: Sequence[Mapping[str, Any]],
    ) -> None:
        normalized_session = str(session_id).strip()
        with self._lock:
            self._steps_by_session[normalized_session] = sorted(
                (
                    self._normalize_step(
                        raw,
                        default_session_id=normalized_session,
                        fallback_order=index + 1,
                    )
                    for index, raw in enumerate(steps)
                ),
                key=lambda row: (int(row["order"]), str(row["id"])),
            )

    def update_step(
        self,
        *,
        session_id: SessionId,
        step_id: str,
        status: str,
        blocked_reason: str = "",
    ) -> bool:
        normalized_session = str(session_id).strip()
        normalized_id = str(step_id).strip()
        normalized_status = normalize_plan_step_status(status)
        with self._lock:
            rows = self._steps_by_session.get(normalized_session, [])
            for row in rows:
                if str(row.get("id", "")) != normalized_id:
                    continue
                row["status"] = normalized_status
                row["current"] = normalized_status in PLAN_STEP_CURRENT_STATUSES
                row["blocked_reason"] = (
                    _safe_display_text(blocked_reason, limit=120)
                    if normalized_status == "blocked"
                    else ""
                )
                row["updated_at"] = datetime.now(UTC).isoformat()
                return True
        return False

    def clear_session(self, *, session_id: SessionId) -> None:
        normalized_session = str(session_id).strip()
        with self._lock:
            self._steps_by_session.pop(normalized_session, None)

    def list_steps(
        self,
        *,
        session_id: SessionId | None = None,
        limit: int = 20,
        active_only: bool = False,
    ) -> list[dict[str, Any]]:
        max_rows = max(0, int(limit))
        with self._lock:
            if session_id is not None and str(session_id).strip():
                rows = list(self._steps_by_session.get(str(session_id).strip(), []))
            else:
                rows = []
                for session_rows in self._steps_by_session.values():
                    if active_only and not self._session_has_active_plan(session_rows):
                        continue
                    rows.extend(session_rows)
        if active_only and session_id is not None and not self._session_has_active_plan(rows):
            rows = []
        rows.sort(
            key=lambda row: (
                str(row.get("session_id", "")),
                int(row.get("order", 0)),
                str(row.get("id", "")),
            )
        )
        return [dict(row) for row in rows[:max_rows]]

    @staticmethod
    def _session_has_active_plan(rows: Sequence[Mapping[str, Any]]) -> bool:
        return any(
            bool(row.get("current", False))
            and normalize_plan_step_status(row.get("status", "")) in PLAN_STEP_CURRENT_STATUSES
            for row in rows
        )

    @staticmethod
    def _normalize_step(
        raw: Mapping[str, Any],
        *,
        default_session_id: str,
        fallback_order: int,
    ) -> dict[str, Any]:
        status = normalize_plan_step_status(raw.get("status", "pending"))
        step_id = _safe_display_text(raw.get("id", ""), fallback=f"step-{fallback_order}", limit=80)
        order = raw.get("order", fallback_order)
        try:
            order_value = int(order)
        except (TypeError, ValueError):
            order_value = fallback_order
        depends_raw = raw.get("depends_on", [])
        depends_on = (
            [
                _safe_display_text(item, limit=80)
                for item in depends_raw
                if _safe_display_text(item, limit=80)
            ]
            if isinstance(depends_raw, list)
            else []
        )
        current = bool(raw.get("current", False)) and status in PLAN_STEP_CURRENT_STATUSES
        return {
            "id": step_id,
            "session_id": _safe_display_text(
                raw.get("session_id", default_session_id),
                fallback=default_session_id,
                limit=80,
            ),
            "plan_hash": _safe_display_text(raw.get("plan_hash", ""), limit=80),
            "order": max(1, order_value),
            "title": _safe_display_text(raw.get("title", ""), fallback="Current request"),
            "status": status,
            "current": current,
            "depends_on": depends_on,
            "blocked_reason": (
                _safe_display_text(raw.get("blocked_reason", ""), limit=120)
                if status == "blocked"
                else ""
            ),
            "updated_at": _safe_display_text(
                raw.get("updated_at", datetime.now(UTC).isoformat()),
                limit=80,
            ),
        }
