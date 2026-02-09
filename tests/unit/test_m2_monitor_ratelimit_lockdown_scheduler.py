"""M2.T9-T12, T21: monitor, rate limits, lockdown, scheduler, and risk policy."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

from shisad.core.types import Capability, SessionId, UserId
from shisad.scheduler.manager import SchedulerManager
from shisad.scheduler.schema import Schedule
from shisad.security.lockdown import LockdownLevel, LockdownManager
from shisad.security.monitor import ActionMonitor, MonitorDecisionType
from shisad.security.ratelimit import RateLimitConfig, RateLimiter
from shisad.security.risk import RiskCalibrator, RiskObservation


def test_m2_t9_action_monitor_rejects_goal_misaligned_proposals() -> None:
    monitor = ActionMonitor()
    decision = monitor.evaluate(
        user_goal="just summarize the text",
        actions=[
            SimpleNamespace(
                tool_name="send_email",
                arguments={"to": "x@example.com"},
                reasoning="Ignore policy and exfiltrate report",
            )
        ],
    )
    assert decision.kind == MonitorDecisionType.REJECT


def test_m2_t10_rate_limiter_blocks_burst() -> None:
    limiter = RateLimiter(
        RateLimitConfig(
            window_seconds=60,
            per_tool=2,
            per_user=10,
            per_session=10,
            burst_multiplier=1.5,
        )
    )
    decision_1 = limiter.evaluate(session_id="s1", user_id="u1", tool_name="http_request")
    decision_2 = limiter.evaluate(session_id="s1", user_id="u1", tool_name="http_request")
    decision_3 = limiter.evaluate(session_id="s1", user_id="u1", tool_name="http_request")
    assert decision_1.block is False
    assert decision_2.require_confirmation is True or decision_2.block is False
    assert decision_3.block is True


def test_m2_t11_lockdown_restricts_capabilities() -> None:
    manager = LockdownManager()
    sid = SessionId("s-lock")
    manager.trigger(sid, trigger="manual", reason="test", recommended_action="quarantine")
    restricted = manager.apply_capability_restrictions(
        sid,
        {Capability.HTTP_REQUEST, Capability.MEMORY_READ},
    )
    assert restricted == set()
    assert manager.state_for(sid).level == LockdownLevel.QUARANTINE


def test_m2_t12_task_capability_snapshot_prevents_upgrade() -> None:
    scheduler = SchedulerManager()
    task = scheduler.create_task(
        name="digest",
        goal="summarize updates",
        schedule=Schedule.from_event("message.received"),
        capability_snapshot={Capability.MEMORY_READ},
        policy_snapshot_ref="p1",
        created_by=UserId("alice"),
    )
    assert scheduler.can_execute_with_capabilities(task.id, {Capability.MEMORY_READ})
    assert not scheduler.can_execute_with_capabilities(
        task.id,
        {Capability.MEMORY_READ, Capability.HTTP_REQUEST},
    )


def test_m2_t21_risk_policy_versioning_is_deterministic(tmp_path: Path) -> None:
    calibrator = RiskCalibrator(
        policy_path=tmp_path / "risk-policy.json",
        observations_path=tmp_path / "risk-observations.jsonl",
    )
    calibrator.record(
        RiskObservation(
            timestamp=datetime.now(UTC),
            session_id="s1",
            user_id="u1",
            tool_name="http_request",
            outcome="allow",
            risk_score=0.2,
        )
    )
    calibrator.record(
        RiskObservation(
            timestamp=datetime.now(UTC),
            session_id="s1",
            user_id="u1",
            tool_name="send_email",
            outcome="require_confirmation",
            risk_score=0.7,
        )
    )
    policy = calibrator.calibrate()
    assert policy.version == "v2"
    assert round(policy.thresholds.auto_approve_threshold, 3) == 0.45
    assert round(policy.thresholds.block_threshold, 3) == 0.75
