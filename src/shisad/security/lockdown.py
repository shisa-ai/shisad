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
        state_change_hook: Callable[[SessionId, LockdownState], None] | None = None,
    ) -> None:
        self._states: dict[SessionId, LockdownState] = {}
        self._notification_hook = notification_hook
        self._state_change_hook = state_change_hook

    def state_for(self, session_id: SessionId) -> LockdownState:
        state = self._states.get(session_id)
        if state is None:
            state = LockdownState(session_id=session_id)
            self._states[session_id] = state
        return state

    def peek_state_for(self, session_id: SessionId) -> LockdownState:
        """Return current state without creating a stored default."""
        return self._states.get(session_id) or LockdownState(session_id=session_id)

    def explicit_states(self) -> list[LockdownState]:
        """Return states that represent an explicit lockdown transition."""
        return [
            state
            for state in self._states.values()
            if (state.level != LockdownLevel.NORMAL or bool(state.reason) or bool(state.trigger))
        ]

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
            state = self._set_state(
                session_id=session_id,
                level=target,
                reason=reason,
                trigger=trigger,
            )
        return state

    def set_level(
        self,
        session_id: SessionId,
        *,
        level: LockdownLevel,
        reason: str,
        trigger: str = "manual",
    ) -> LockdownState:
        """Manually set lockdown level, supporting both escalation and recovery."""
        return self._set_state(
            session_id=session_id,
            level=level,
            reason=reason,
            trigger=trigger,
        )

    def resume(self, session_id: SessionId, *, reason: str = "manual_resume") -> LockdownState:
        """Reset a session to NORMAL from any lockdown state."""
        return self.set_level(
            session_id,
            level=LockdownLevel.NORMAL,
            reason=reason,
            trigger="manual_resume",
        )

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
        # Operator-facing recovery guidance. Name both the in-chat path (the
        # trusted operator can ask the agent to resume the lockdown once the
        # cause is understood) and the out-of-band CLI path with the session
        # id so single-surface operators always have a copy-pasteable
        # command. See `review/LUS-9.md` Phase C for the dead-end this fixes.
        recovery_cli = f"shisad lockdown resume {session_id} --reason <note>"
        return (
            f"Session is in {state.level.value} due to {state.trigger}: {state.reason}. "
            f"To recover: ask the agent to resume the lockdown when ready, "
            f"or run `{recovery_cli}` from the trusted CLI. "
            f"Session id: {session_id}."
        )

    def snapshot(self, session_id: SessionId, *, include_default: bool = True) -> dict[str, object]:
        state = self.state_for(session_id) if include_default else self._states.get(session_id)
        if state is None:
            return {}
        return state.model_dump(mode="json")

    def rehydrate(
        self,
        session_id: SessionId,
        snapshot: object,
        *,
        notify: bool = False,
    ) -> LockdownState:
        if snapshot in (None, {}):
            return self.state_for(session_id)
        payload = LockdownState.model_validate(snapshot)
        if payload.session_id != session_id:
            raise ValueError("lockdown snapshot session_id mismatch")
        self._states[session_id] = payload
        if self._state_change_hook is not None:
            self._state_change_hook(session_id, payload)
        if notify:
            self._notify(session_id, payload)
        return payload

    def clear_state(self, session_id: SessionId) -> None:
        self._states.pop(session_id, None)

    def _target_level(self, *, trigger: str, recommended_action: str) -> LockdownLevel:
        action = recommended_action.lower().strip()
        if action in {"normal", "resume", "clear"}:
            return LockdownLevel.NORMAL
        if action in {"caution"}:
            return LockdownLevel.CAUTION
        if action in {"lockdown", "full_lockdown"}:
            return LockdownLevel.FULL_LOCKDOWN
        if action in {"quarantine"}:
            return LockdownLevel.QUARANTINE
        if trigger in {"rate_limit", "monitor_reject"}:
            return LockdownLevel.CAUTION
        return LockdownLevel.CAUTION

    def level_for_action(self, action: str, *, trigger: str = "manual") -> LockdownLevel:
        return self._target_level(trigger=trigger, recommended_action=action)

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

    def _set_state(
        self,
        *,
        session_id: SessionId,
        level: LockdownLevel,
        reason: str,
        trigger: str,
    ) -> LockdownState:
        state = LockdownState(
            session_id=session_id,
            level=level,
            reason=reason,
            trigger=trigger,
            updated_at=datetime.now(UTC),
        )
        self._states[session_id] = state
        if self._state_change_hook is not None:
            self._state_change_hook(session_id, state)
        self._notify(session_id, state)
        return state
