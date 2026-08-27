"""Bounded redacted action-progress projection for user surfaces."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel

from shisad.core.events import BaseEvent, ToolApproved, ToolExecuted, ToolRejected
from shisad.core.types import PEPDecisionKind

ProgressState = Literal[
    "running",
    "awaiting_confirmation",
    "rejected",
    "succeeded",
    "failed",
]

_TOOL_NAME_LIMIT = 64
_TOOL_NAME_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")


class ActionProgressView(BaseModel, frozen=True):
    """Least-privilege, non-durable action lifecycle view."""

    event_type: Literal["ActionProgress"] = "ActionProgress"
    session_id: str
    action_id: str
    origin_turn_id: str
    tool_name: str
    state: ProgressState


def _safe_tool_name(value: object) -> str:
    bounded = "".join(character for character in str(value) if character in _TOOL_NAME_CHARS)
    return bounded[:_TOOL_NAME_LIMIT] or "tool"


def project_action_progress(event: BaseEvent) -> ActionProgressView | None:
    """Project one typed audit event without arguments, output, or reason prose."""
    if isinstance(event, ToolApproved):
        state: ProgressState = "running"
    elif isinstance(event, ToolRejected):
        state = (
            "awaiting_confirmation"
            if event.decision == PEPDecisionKind.REQUIRE_CONFIRMATION
            else "rejected"
        )
    elif isinstance(event, ToolExecuted):
        state = "succeeded" if event.success else "failed"
    else:
        return None

    session_id = str(event.session_id or "").strip()
    action_id = str(getattr(event, "action_id", "") or "").strip()
    origin_turn_id = str(getattr(event, "origin_turn_id", "") or "").strip()
    if not session_id or not action_id or not origin_turn_id:
        return None
    return ActionProgressView(
        session_id=session_id,
        action_id=action_id,
        origin_turn_id=origin_turn_id,
        tool_name=_safe_tool_name(getattr(event, "tool_name", "")),
        state=state,
    )


def format_action_progress_line(progress: ActionProgressView) -> str:
    """Render one bounded plain-text line from safe fields only."""
    marker = {
        "running": "…",
        "awaiting_confirmation": "?",
        "rejected": "x",
        "succeeded": "✓",
        "failed": "!",
    }[progress.state]
    return f"{marker} {progress.tool_name} — {progress.state}"
