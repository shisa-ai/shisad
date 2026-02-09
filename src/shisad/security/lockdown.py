"""Per-session lockdown manager."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field

from shisad.core.types import Capability, SessionId

_SIDE_EFFECT_CAPS = {
    Capability.EMAIL_SEND,
    Capability.EMAIL_WRITE,
    Capability.FILE_WRITE,
    Capability.HTTP_REQUEST,
    Capability.MESSAGE_SEND,
    Capability.SHELL_EXEC,
    Capability.CALENDAR_WRITE,
}


class LockdownLevel(StrEnum):
    NORMAL = "normal"
    CAUTION = "caution"
    QUARANTINE = "quarantine"
    FULL_LOCKDOWN = "full_lockdown"


class LockdownState(BaseModel):
    session_id: SessionId
    level: LockdownLevel = LockdownLevel.NORMAL
    reason: str = ""
    trigger: str = ""
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class LockdownManager:
    """State machine for escalation under suspicious behavior."""

    def __init__(
        self,
        *,
        notification_hook: Callable[[SessionId, str], None] | None = None,
    ) -> None:
        self._states: dict[SessionId, LockdownState] = {}
        self._notification_hook = notification_hook

    def state_for(self, session_id: SessionId) -> LockdownState:
        state = self._states.get(session_id)
        if state is None:
            state = LockdownState(session_id=session_id)
            self._states[session_id] = state
        return state

    def trigger(
        self,
        session_id: SessionId,
        *,
        trigger: str,
        reason: str,
        recommended_action: str = "",
    ) -> LockdownState:
        state = self.state_for(session_id)
        target = self._target_level(trigger=trigger, recommended_action=recommended_action)
        if self._rank(target) > self._rank(state.level):
            state = LockdownState(
                session_id=session_id,
                level=target,
                reason=reason,
                trigger=trigger,
                updated_at=datetime.now(UTC),
            )
            self._states[session_id] = state
            self._notify(session_id, state)
        return state

    def apply_capability_restrictions(
        self,
        session_id: SessionId,
        capabilities: set[Capability],
    ) -> set[Capability]:
        level = self.state_for(session_id).level
        if level == LockdownLevel.NORMAL:
            return set(capabilities)
        if level == LockdownLevel.CAUTION:
            return set(capabilities) - _SIDE_EFFECT_CAPS
        if level in {LockdownLevel.QUARANTINE, LockdownLevel.FULL_LOCKDOWN}:
            return set()
        return set(capabilities)

    def should_block_all_actions(self, session_id: SessionId) -> bool:
        level = self.state_for(session_id).level
        return level in {LockdownLevel.QUARANTINE, LockdownLevel.FULL_LOCKDOWN}

    def user_notification(self, session_id: SessionId) -> str:
        state = self.state_for(session_id)
        if state.level == LockdownLevel.NORMAL:
            return ""
        return (
            f"Session is in {state.level.value} due to {state.trigger}: {state.reason}. "
            "Review, escalate, resume, or terminate via control API."
        )

    def _target_level(self, *, trigger: str, recommended_action: str) -> LockdownLevel:
        action = recommended_action.lower().strip()
        if action in {"lockdown", "full_lockdown"}:
            return LockdownLevel.FULL_LOCKDOWN
        if action in {"quarantine"}:
            return LockdownLevel.QUARANTINE
        if trigger in {"rate_limit", "monitor_reject"}:
            return LockdownLevel.CAUTION
        return LockdownLevel.CAUTION

    @staticmethod
    def _rank(level: LockdownLevel) -> int:
        ranks = {
            LockdownLevel.NORMAL: 0,
            LockdownLevel.CAUTION: 1,
            LockdownLevel.QUARANTINE: 2,
            LockdownLevel.FULL_LOCKDOWN: 3,
        }
        return ranks[level]

    def _notify(self, session_id: SessionId, state: LockdownState) -> None:
        if self._notification_hook is None:
            return
        self._notification_hook(
            session_id,
            (
                f"Lockdown changed to {state.level.value}: "
                f"trigger={state.trigger}, reason={state.reason}"
            ),
        )

