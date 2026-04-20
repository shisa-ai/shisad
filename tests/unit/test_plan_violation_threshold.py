"""Runtime loop guard tests for plan-violation escalation behavior."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from shisad.core.events import PlanViolationDetected
from shisad.core.types import SessionId, ToolName
from shisad.daemon.handlers._impl import HandlerImplementation
from shisad.security.control_plane.schema import ActionKind, RiskTier


class _PlanViolationHarness:
    def __init__(self, *, threshold: int) -> None:
        self._plan_violation_counts: dict[SessionId, int] = {}
        self._policy_loader = SimpleNamespace(
            policy=SimpleNamespace(
                control_plane=SimpleNamespace(trace=SimpleNamespace(escalation_threshold=threshold))
            )
        )
        self.events: list[object] = []
        self.lockdown_calls: list[tuple[SessionId, str, str]] = []
        self._event_bus = SimpleNamespace(publish=self._publish)

    async def _publish(self, event: object) -> None:
        self.events.append(event)

    async def _handle_lockdown_transition(
        self,
        sid: SessionId,
        *,
        trigger: str,
        reason: str,
        recommended_action: str = "",
    ) -> None:
        _ = recommended_action
        self.lockdown_calls.append((sid, trigger, reason))


@pytest.mark.asyncio
async def test_m1_rlc2_high_risk_plan_violation_respects_threshold_before_lockdown() -> None:
    harness = _PlanViolationHarness(threshold=2)
    sid = SessionId("sess-threshold")

    await HandlerImplementation._record_plan_violation(
        harness,  # type: ignore[arg-type]
        sid=sid,
        tool_name=ToolName("unknown.tool"),
        action_kind=ActionKind.UNKNOWN,
        reason_code="trace:action_not_committed",
        risk_tier=RiskTier.HIGH,
    )

    assert harness._plan_violation_counts[sid] == 1
    assert len(harness.events) == 1
    assert harness.lockdown_calls == []

    # PLN-L1: pin the exact event payload so a regression that emits the
    # wrong event type, drops the reason_code, or swaps action_kind/risk_tier
    # values would fail loudly. Prior assertions only checked event count.
    event = harness.events[0]
    assert isinstance(event, PlanViolationDetected)
    assert event.session_id == sid
    assert event.tool_name == ToolName("unknown.tool")
    assert event.action_kind == ActionKind.UNKNOWN.value
    assert event.reason_code == "trace:action_not_committed"
    assert event.risk_tier == RiskTier.HIGH.value


@pytest.mark.asyncio
async def test_m1_rlc2_high_risk_plan_violation_locks_after_threshold() -> None:
    harness = _PlanViolationHarness(threshold=2)
    sid = SessionId("sess-threshold")

    for _ in range(2):
        await HandlerImplementation._record_plan_violation(
            harness,  # type: ignore[arg-type]
            sid=sid,
            tool_name=ToolName("unknown.tool"),
            action_kind=ActionKind.UNKNOWN,
            reason_code="trace:action_not_committed",
            risk_tier=RiskTier.HIGH,
        )

    assert harness._plan_violation_counts[sid] == 2
    assert len(harness.events) == 2
    assert len(harness.lockdown_calls) == 1
    # PLN-L1: pin the full lockdown-call argument shape, including the
    # "<reason_code> (<count>)" reason formatting. Prior assertion only
    # pinned the trigger string.
    called_sid, trigger, reason = harness.lockdown_calls[0]
    assert called_sid == sid
    assert trigger == "plan_violation"
    assert reason == "trace:action_not_committed (2)"


@pytest.mark.asyncio
async def test_m1_rlc2_threshold_of_zero_clamps_to_one_and_locks_on_first_violation() -> None:
    # PLN-L1 follow-up: cover the `max(1, threshold)` clamp so a regression
    # that drops the clamp (accidentally tolerating threshold<=0 →
    # "never lock") would fail immediately. Without the clamp, count (1) >=
    # threshold (0) is still true on the first call — but a bug that
    # changed `count >= threshold` to `count > threshold` would silently
    # stop locking. The clamp is the actual defense.
    harness = _PlanViolationHarness(threshold=0)
    sid = SessionId("sess-zero-threshold")

    await HandlerImplementation._record_plan_violation(
        harness,  # type: ignore[arg-type]
        sid=sid,
        tool_name=ToolName("unknown.tool"),
        action_kind=ActionKind.UNKNOWN,
        reason_code="trace:action_not_committed",
        risk_tier=RiskTier.HIGH,
    )

    assert harness._plan_violation_counts[sid] == 1
    assert len(harness.lockdown_calls) == 1
    assert harness.lockdown_calls[0][1] == "plan_violation"
