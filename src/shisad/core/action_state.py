"""Typed action identity and lifecycle projections shared by runtime surfaces."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal

CURRENT_TURN_REMINDER_CREATE_INTENT = "current_turn_reminder_create"

ActionLifecycleState = Literal[
    "pending",
    "executing",
    "executed",
    "rejected",
    "expired",
    "failed",
    "cancelled",
    "superseded",
    "outcome_unknown",
]

_ACTION_STATUS_TO_LIFECYCLE: dict[str, ActionLifecycleState] = {
    "pending": "pending",
    "executing": "executing",
    "approved": "executed",
    "executed": "executed",
    "rejected": "rejected",
    "expired": "expired",
    "failed": "failed",
    "cancelled": "cancelled",
    "canceled": "cancelled",
    "superseded": "superseded",
    "outcome_unknown": "outcome_unknown",
}


@dataclass(frozen=True, slots=True)
class ActionIdentity:
    """End-to-end identity shared by approval, execution, result, and follow-up."""

    action_id: str
    origin_turn_id: str
    session_id: str
    user_id: str
    workspace_id: str
    task_id: str
    delivery_target: tuple[tuple[str, str], ...]
    confirmation_id: str
    execution_attempt_id: str
    result_id: str
    followup_id: str

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> ActionIdentity:
        """Parse an identity projection without accepting non-structural targets."""

        raw_delivery_target = payload.get("delivery_target")
        if raw_delivery_target is None or raw_delivery_target == "":
            delivery_target: tuple[tuple[str, str], ...] = ()
        elif isinstance(raw_delivery_target, Mapping):
            delivery_target = tuple(
                sorted(
                    (str(key), str(value))
                    for key, value in raw_delivery_target.items()
                    if value is not None
                )
            )
        else:
            raise ValueError("delivery_target must be a mapping or null")

        def _text(key: str) -> str:
            value = payload.get(key)
            return "" if value is None else str(value).strip()

        return cls(
            action_id=_text("action_id"),
            origin_turn_id=_text("origin_turn_id"),
            session_id=_text("session_id"),
            user_id=_text("user_id"),
            workspace_id=_text("workspace_id"),
            task_id=_text("task_id"),
            delivery_target=delivery_target,
            confirmation_id=_text("confirmation_id"),
            execution_attempt_id=_text("execution_attempt_id"),
            result_id=_text("result_id"),
            followup_id=_text("followup_id"),
        )

    @property
    def is_complete_result_followup(self) -> bool:
        """Return whether a terminal result has a fully bound continuation identity."""

        required = (
            self.action_id,
            self.origin_turn_id,
            self.session_id,
            self.user_id,
            self.workspace_id,
            self.confirmation_id,
            self.execution_attempt_id,
            self.result_id,
            self.followup_id,
        )
        operation_ids = {
            self.action_id,
            self.confirmation_id,
            self.execution_attempt_id,
            self.result_id,
            self.followup_id,
        }
        return all(required) and len(operation_ids) == 5

    def to_payload(self) -> dict[str, Any]:
        return {
            "action_id": self.action_id,
            "origin_turn_id": self.origin_turn_id,
            "session_id": self.session_id,
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "task_id": self.task_id,
            "delivery_target": dict(self.delivery_target) if self.delivery_target else None,
            "confirmation_id": self.confirmation_id,
            "execution_attempt_id": self.execution_attempt_id,
            "result_id": self.result_id,
            "followup_id": self.followup_id,
        }


@dataclass(frozen=True, slots=True)
class ActionStateView:
    """Canonical, mutually exclusive lifecycle projection for runtime surfaces."""

    identity: ActionIdentity
    lifecycle_state: ActionLifecycleState
    status_reason: str
    created_at: datetime
    expires_at: datetime | None

    @property
    def is_live_pending(self) -> bool:
        return self.lifecycle_state == "pending"


def derive_legacy_action_id(
    *,
    confirmation_id: str,
    session_id: str,
    created_at: datetime | str,
) -> str:
    """Derive a stable distinct operation ID for pre-F1 pending rows."""
    created = created_at.isoformat() if isinstance(created_at, datetime) else str(created_at)
    digest = hashlib.sha256(
        f"legacy-pending-action\x00{session_id}\x00{confirmation_id}\x00{created}".encode()
    ).hexdigest()
    return f"act-{digest[:32]}"


def derive_action_result_id(action_id: str) -> str:
    digest = hashlib.sha256(f"action-result\x00{action_id}".encode()).hexdigest()
    return f"result-{digest[:32]}"


def derive_action_followup_id(action_id: str) -> str:
    digest = hashlib.sha256(f"action-followup\x00{action_id}".encode()).hexdigest()
    return f"followup-{digest[:32]}"


def action_lifecycle_state(
    *,
    status: str,
    status_reason: str = "",
    expires_at: datetime | None = None,
    now: datetime | None = None,
) -> ActionLifecycleState:
    """Project compatibility status fields into one canonical lifecycle state."""
    normalized_status = str(status or "pending").strip().casefold() or "pending"
    normalized_reason = str(status_reason or "").strip().casefold()
    if normalized_reason == "approval_expired" and normalized_status in {
        "pending",
        "failed",
        "expired",
    }:
        return "expired"
    if normalized_reason == "purged_stale_pending_action" and normalized_status in {
        "pending",
        "failed",
        "superseded",
    }:
        return "superseded"
    if normalized_status == "pending" and isinstance(expires_at, datetime):
        current = now or datetime.now(expires_at.tzinfo or UTC)
        comparable_expiry = expires_at
        if comparable_expiry.tzinfo is None and current.tzinfo is not None:
            current = current.replace(tzinfo=None)
        elif comparable_expiry.tzinfo is not None and current.tzinfo is None:
            current = current.replace(tzinfo=comparable_expiry.tzinfo)
        if comparable_expiry <= current:
            return "expired"
    return _ACTION_STATUS_TO_LIFECYCLE.get(normalized_status, "failed")


ReminderLifecycleState = Literal[
    "pending",
    "executing",
    "executed",
    "failed",
    "cancelled",
]

ReminderDurationUnit = Literal["seconds", "minutes", "hours"]

_REMINDER_DURATION_UNIT_ALIASES: dict[str, ReminderDurationUnit] = {
    "s": "seconds",
    "sec": "seconds",
    "secs": "seconds",
    "second": "seconds",
    "seconds": "seconds",
    "m": "minutes",
    "min": "minutes",
    "mins": "minutes",
    "minute": "minutes",
    "minutes": "minutes",
    "h": "hours",
    "hr": "hours",
    "hrs": "hours",
    "hour": "hours",
    "hours": "hours",
}


def current_turn_value_is_structurally_anchored(
    value: Any,
    *,
    normalized_current_turn: str,
) -> bool:
    """Require a whole-token value occurrence in daemon-owned current-turn text."""
    if not isinstance(value, str):
        return False
    normalized = " ".join(value.split()).casefold()
    if not normalized:
        return False
    current_turn = str(normalized_current_turn or "").casefold()
    start = 0
    while True:
        index = current_turn.find(normalized, start)
        if index < 0:
            return False
        before_index = index - 1
        after_index = index + len(normalized)
        before_ok = before_index < 0 or not _current_turn_anchor_token_char(
            current_turn[before_index]
        )
        after_ok = after_index >= len(current_turn) or _current_turn_anchor_after_boundary_ok(
            current_turn,
            after_index,
        )
        if before_ok and after_ok:
            return True
        start = index + 1


def _current_turn_anchor_token_char(char: str) -> bool:
    return char.isalnum() or char in {"_", "-", ".", "@", "/", ":", "~"}


def _current_turn_anchor_after_boundary_ok(text: str, index: int) -> bool:
    char = text[index]
    if not _current_turn_anchor_token_char(char):
        return True
    if char not in {".", ":"}:
        return False
    next_index = index + 1
    return next_index >= len(text) or not _current_turn_anchor_token_char(text[next_index])


@dataclass(frozen=True, slots=True)
class ReminderRelativeDuration:
    value: int
    unit: ReminderDurationUnit

    @property
    def seconds(self) -> int:
        multiplier = {"seconds": 1, "minutes": 60, "hours": 3600}[self.unit]
        return self.value * multiplier


def parse_reminder_relative_duration(value: str) -> ReminderRelativeDuration | None:
    """Parse the finite machine-facing `reminder.create.when` duration grammar."""
    parts = str(value or "").casefold().split()
    if len(parts) != 3 or parts[0] != "in" or not parts[1].isdigit():
        return None
    unit = _REMINDER_DURATION_UNIT_ALIASES.get(parts[2])
    if unit is None:
        return None
    return ReminderRelativeDuration(value=max(1, int(parts[1])), unit=unit)


def _current_turn_tokens(value: str) -> tuple[str, ...]:
    normalized = "".join(
        character if character.isalnum() else " " for character in str(value).casefold()
    )
    return tuple(normalized.split())


def _token_sequence_present(
    haystack: tuple[str, ...],
    needle: tuple[str, ...],
) -> bool:
    if not needle or len(needle) > len(haystack):
        return False
    return any(
        haystack[index : index + len(needle)] == needle
        for index in range(len(haystack) - len(needle) + 1)
    )


def _reminder_when_is_current_turn_anchored(*, when: str, current_turn: str) -> bool:
    normalized_turn = " ".join(str(current_turn or "").split()).casefold()
    if current_turn_value_is_structurally_anchored(
        when,
        normalized_current_turn=normalized_turn,
    ):
        return True

    duration = parse_reminder_relative_duration(when)
    current_tokens = _current_turn_tokens(current_turn)
    if duration is not None:
        for index in range(len(current_tokens) - 1):
            if current_tokens[index] != str(duration.value):
                continue
            if _REMINDER_DURATION_UNIT_ALIASES.get(current_tokens[index + 1]) == duration.unit:
                return True
        return False

    when_tokens = _current_turn_tokens(when)
    if when_tokens and when_tokens[0] == "at":
        return _token_sequence_present(current_tokens, when_tokens[1:])
    return False


def reminder_create_arguments_are_current_turn_anchored(
    arguments: Mapping[str, Any],
    *,
    current_turn: str,
) -> bool:
    """Bind reminder content and finite schedule fields to the current user turn."""
    allowed_fields = {"message", "when", "name", "reminder_intent"}
    if not set(arguments).issubset(allowed_fields):
        return False
    message = arguments.get("message")
    when = arguments.get("when")
    if not isinstance(message, str) or not message.strip():
        return False
    if not isinstance(when, str) or not when.strip():
        return False
    normalized_turn = " ".join(str(current_turn or "").split()).casefold()
    if not normalized_turn or not current_turn_value_is_structurally_anchored(
        message,
        normalized_current_turn=normalized_turn,
    ):
        return False
    name = arguments.get("name")
    if name is not None and (
        not isinstance(name, str)
        or not name.strip()
        or not current_turn_value_is_structurally_anchored(
            name,
            normalized_current_turn=normalized_turn,
        )
    ):
        return False
    marker = arguments.get("reminder_intent")
    if marker is not None and marker != CURRENT_TURN_REMINDER_CREATE_INTENT:
        return False
    return _reminder_when_is_current_turn_anchored(
        when=when,
        current_turn=current_turn,
    )


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
    active = [item for item in current if item.lifecycle_state in {"pending", "executing"}]
    candidates = tuple(active or current)
    if len(candidates) > 1:
        return ReminderStatusSelection(status="ambiguous", candidates=candidates)
    return ReminderStatusSelection(
        status="selected",
        candidates=candidates,
        selected=candidates[0],
    )
