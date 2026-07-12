"""Typed action identity and lifecycle projections shared by runtime surfaces."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal

ReminderLifecycleState = Literal[
    "pending",
    "executing",
    "executed",
    "failed",
    "cancelled",
]


@dataclass(frozen=True, slots=True)
class ReminderActionIdentity:
    """Daemon-owned identity binding for a scheduled reminder projection."""

    task_id: str
    session_id: str
    user_id: str
    workspace_id: str
    delivery_target: tuple[tuple[str, str], ...]


@dataclass(frozen=True, slots=True)
class ReminderStatusView:
    identity: ReminderActionIdentity
    message: str
    lifecycle_state: ReminderLifecycleState
    current_binding: bool
    created_at: datetime
    last_triggered_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class ReminderStatusSelection:
    status: Literal["none", "selected", "ambiguous"]
    candidates: tuple[ReminderStatusView, ...] = ()
    selected: ReminderStatusView | None = None


def reminder_lifecycle_state(
    *,
    enabled: bool,
    pending_confirmation_count: int,
    trigger_count: int,
    max_runs: int,
    success_count: int,
    failure_count: int,
) -> ReminderLifecycleState:
    """Project scheduler counters into one mutually exclusive reminder state."""
    if pending_confirmation_count > 0:
        return "pending"
    if max_runs > 0 and trigger_count >= max_runs:
        if success_count >= max_runs:
            return "executed"
        if success_count + failure_count >= trigger_count and failure_count > 0:
            return "failed"
        return "executing"
    if not enabled:
        return "cancelled"
    if trigger_count > success_count + failure_count:
        return "executing"
    return "pending"


def reminder_status_view_for_task(
    task: Any,
    *,
    current_delivery_target: Mapping[str, Any],
    pending_confirmation_count: int = 0,
) -> ReminderStatusView | None:
    """Build the canonical reminder view from persisted scheduler state."""
    task_id = str(getattr(task, "id", "")).strip()
    goal = str(getattr(task, "goal", "")).strip()
    created_at = getattr(task, "created_at", None)
    if not task_id or not goal.startswith("Reminder: ") or not isinstance(created_at, datetime):
        return None

    def _target_items(raw: Any) -> tuple[tuple[str, str], ...]:
        if not isinstance(raw, Mapping):
            return ()
        return tuple(
            sorted(
                (str(key), str(value))
                for key, value in raw.items()
                if value is not None and str(value).strip()
            )
        )

    delivery_target = _target_items(getattr(task, "delivery_target", None))
    current_target = _target_items(current_delivery_target)
    delivery_target_map = dict(delivery_target)
    lifecycle_state = reminder_lifecycle_state(
        enabled=bool(getattr(task, "enabled", True)),
        pending_confirmation_count=pending_confirmation_count,
        trigger_count=int(getattr(task, "trigger_count", 0) or 0),
        max_runs=int(getattr(task, "max_runs", 0) or 0),
        success_count=int(getattr(task, "success_count", 0) or 0),
        failure_count=int(getattr(task, "failure_count", 0) or 0),
    )
    last_triggered_at = getattr(task, "last_triggered_at", None)
    return ReminderStatusView(
        identity=ReminderActionIdentity(
            task_id=task_id,
            session_id=(
                delivery_target_map.get("recipient", "")
                if delivery_target_map.get("channel") == "session"
                else ""
            ),
            user_id=str(getattr(task, "created_by", "")).strip(),
            workspace_id=str(getattr(task, "workspace_id", "")).strip(),
            delivery_target=delivery_target,
        ),
        message=goal.removeprefix("Reminder: ").strip(),
        lifecycle_state=lifecycle_state,
        current_binding=bool(delivery_target) and delivery_target == current_target,
        created_at=created_at,
        last_triggered_at=(last_triggered_at if isinstance(last_triggered_at, datetime) else None),
    )


def select_reminder_status_view(
    reminders: Sequence[ReminderStatusView],
) -> ReminderStatusSelection:
    """Select only a uniquely bound live reminder; otherwise require disambiguation."""
    ordered = sorted(
        reminders,
        key=lambda item: (item.created_at, item.identity.task_id),
        reverse=True,
    )
    if not ordered:
        return ReminderStatusSelection(status="none")
    current = [item for item in ordered if item.current_binding]
    if not current:
        return ReminderStatusSelection(status="none")
    active = [
        item for item in current if item.lifecycle_state in {"pending", "executing"}
    ]
    candidates = tuple(active or current)
    if len(candidates) > 1:
        return ReminderStatusSelection(status="ambiguous", candidates=candidates)
    return ReminderStatusSelection(
        status="selected",
        candidates=candidates,
        selected=candidates[0],
    )
