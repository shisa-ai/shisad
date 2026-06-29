"""Unit checks for session.terminate runtime ownership guards."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from shisad.core.plan_steps import PlanStepStore
from shisad.core.session import Session
from shisad.core.types import SessionId, UserId, WorkspaceId
from shisad.daemon.handlers._impl_session import SessionImplMixin


class _SessionManagerStub:
    def __init__(self) -> None:
        self._session = Session(
            id=SessionId("sess-1"),
            channel="cli",
            user_id=UserId("alice"),
            workspace_id=WorkspaceId("w1"),
        )
        self.terminated: list[tuple[SessionId, str]] = []

    def get(self, session_id: SessionId) -> Session | None:
        if str(session_id) == str(self._session.id):
            return self._session
        return None

    def validate_identity_binding(
        self,
        session_id: SessionId,
        *,
        channel: str,
        user_id: UserId,
        workspace_id: WorkspaceId,
    ) -> bool:
        return (
            str(session_id) == str(self._session.id)
            and channel == self._session.channel
            and user_id == self._session.user_id
            and workspace_id == self._session.workspace_id
        )

    def terminate(self, session_id: SessionId, reason: str = "") -> bool:
        self.terminated.append((session_id, reason))
        return str(session_id) == str(self._session.id)


class _Harness(SessionImplMixin):
    def __init__(self) -> None:
        self._session_manager = _SessionManagerStub()
        self._plan_steps = PlanStepStore()
        self._event_bus = SimpleNamespace(publish=self._noop_publish)

    async def _noop_publish(self, _event: object) -> None:
        return None


@pytest.mark.asyncio
async def test_m6_s1_session_terminate_enforces_identity_binding() -> None:
    harness = _Harness()

    with pytest.raises(ValueError, match="Session identity binding mismatch"):
        await harness.do_session_terminate(
            {
                "session_id": "sess-1",
                "channel": "cli",
                "user_id": "mallory",
                "workspace_id": "w1",
            }
        )


@pytest.mark.asyncio
async def test_m6_s1_session_terminate_succeeds_for_bound_owner() -> None:
    harness = _Harness()

    result = await harness.do_session_terminate(
        {
            "session_id": "sess-1",
            "channel": "cli",
            "user_id": "alice",
            "workspace_id": "w1",
            "reason": "prune",
        }
    )

    assert result["terminated"] is True
    assert result["session_id"] == "sess-1"
    assert result["reason"] == "prune"
    assert harness._session_manager.terminated == [(SessionId("sess-1"), "prune")]


@pytest.mark.asyncio
async def test_t1_session_terminate_clears_plan_step_rows() -> None:
    harness = _Harness()
    step_id = harness._plan_steps.start_plan_step(
        session_id=SessionId("sess-1"),
        plan_hash="plan-1",
    )

    assert harness._plan_steps.list_steps(active_only=True)[0]["id"] == step_id

    await harness.do_session_terminate(
        {
            "session_id": "sess-1",
            "channel": "cli",
            "user_id": "alice",
            "workspace_id": "w1",
            "reason": "done",
        }
    )

    assert harness._plan_steps.list_steps(session_id=SessionId("sess-1")) == []
    assert harness._plan_steps.list_steps(active_only=True) == []


@pytest.mark.asyncio
async def test_m6_s1_session_terminate_returns_false_when_missing() -> None:
    harness = _Harness()

    result = await harness.do_session_terminate({"session_id": "unknown"})
    assert result["terminated"] is False
    assert result["session_id"] == "unknown"
