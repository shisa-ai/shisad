"""Runtime loop guard tests for plan-violation escalation behavior."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

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
    assert harness.lockdown_calls[0][1] == "plan_violation"
