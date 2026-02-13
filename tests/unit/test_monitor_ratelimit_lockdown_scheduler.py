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


def test_m2_t10_rate_limiter_check_is_idempotent_until_consume() -> None:
    limiter = RateLimiter(
        RateLimitConfig(window_seconds=60, per_tool=2, per_user=10, per_session=10)
    )
    check_1 = limiter.check(session_id="s1", user_id="u1", tool_name="http_request")
    check_2 = limiter.check(session_id="s1", user_id="u1", tool_name="http_request")
    assert check_1.block is False
    assert check_2.block is False

    limiter.consume(session_id="s1", user_id="u1", tool_name="http_request")
    limiter.consume(session_id="s1", user_id="u1", tool_name="http_request")
    check_3 = limiter.check(session_id="s1", user_id="u1", tool_name="http_request")
    assert check_3.block is True


def test_m2_t10_burst_detection_reachable_before_per_tool_limit() -> None:
    limiter = RateLimiter(
        RateLimitConfig(
            window_seconds=60,
            per_tool=15,
            per_user=100,
            per_session=100,
            burst_multiplier=2.0,
            burst_window_seconds=10,
        )
    )
    decisions = [
        limiter.evaluate(session_id="s1", user_id="u1", tool_name="http_request")
        for _ in range(6)
    ]
    assert all(not decision.block for decision in decisions[:5])
    assert decisions[5].block is True
    assert decisions[5].reason == "burst_detected"


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


def test_m2_t11_lockdown_supports_manual_deescalation_and_resume() -> None:
    manager = LockdownManager()
    sid = SessionId("s-recover")
    manager.trigger(sid, trigger="alarm_bell", reason="critical", recommended_action="quarantine")
    assert manager.state_for(sid).level == LockdownLevel.QUARANTINE

    manager.set_level(sid, level=LockdownLevel.CAUTION, reason="manual review", trigger="manual")
    assert manager.state_for(sid).level == LockdownLevel.CAUTION

    manager.resume(sid, reason="incident resolved")
    assert manager.state_for(sid).level == LockdownLevel.NORMAL


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


def test_m2_t12_task_capability_snapshot_requires_runtime_availability() -> None:
    scheduler = SchedulerManager()
    task = scheduler.create_task(
        name="digest",
        goal="summarize updates",
        schedule=Schedule.from_event("message.received"),
        capability_snapshot={Capability.MEMORY_READ},
        policy_snapshot_ref="p1",
        created_by=UserId("alice"),
    )
    assert scheduler.can_execute_with_capabilities(
        task.id,
        {Capability.MEMORY_READ},
        available_capabilities={Capability.MEMORY_READ, Capability.HTTP_REQUEST},
    )
    assert not scheduler.can_execute_with_capabilities(
        task.id,
        {Capability.MEMORY_READ},
        available_capabilities={Capability.HTTP_REQUEST},
    )


def test_m2_t12_task_commitment_hash_binds_task_identity() -> None:
    scheduler = SchedulerManager()
    task_one = scheduler.create_task(
        name="digest",
        goal="summarize updates",
        schedule=Schedule.from_event("message.received"),
        capability_snapshot={Capability.MEMORY_READ},
        policy_snapshot_ref="p1",
        created_by=UserId("alice"),
    )
    task_two = scheduler.create_task(
        name="digest",
        goal="summarize updates",
        schedule=Schedule.from_event("message.received"),
        capability_snapshot={Capability.MEMORY_READ},
        policy_snapshot_ref="p1",
        created_by=UserId("alice"),
    )
    assert task_one.commitment_hash() != task_two.commitment_hash()


def test_m2_scheduler_hydrates_tasks_after_restart(tmp_path: Path) -> None:
    storage = tmp_path / "tasks"
    first = SchedulerManager(storage_dir=storage)
    created = first.create_task(
        name="digest",
        goal="summarize updates",
        schedule=Schedule.from_event("message.received"),
        capability_snapshot={Capability.MEMORY_READ},
        policy_snapshot_ref="p1",
        created_by=UserId("alice"),
    )
    restarted = SchedulerManager(storage_dir=storage)
    loaded = restarted.get_task(created.id)
    assert loaded is not None
    assert loaded.name == "digest"


def test_m2_scheduler_hydrates_pending_confirmations_after_restart(tmp_path: Path) -> None:
    storage = tmp_path / "tasks"
    first = SchedulerManager(storage_dir=storage)
    created = first.create_task(
        name="digest",
        goal="summarize updates",
        schedule=Schedule.from_event("message.received"),
        capability_snapshot={Capability.MEMORY_READ},
        policy_snapshot_ref="p1",
        created_by=UserId("alice"),
    )
    first.queue_confirmation(
        created.id,
        {
            "task_id": created.id,
            "event_type": "message.received",
            "trigger_payload": "hello",
            "plan_commitment": created.commitment_hash(),
            "payload_taint": "UNTRUSTED",
            "status": "pending",
        },
    )

    restarted = SchedulerManager(storage_dir=storage)
    pending = restarted.pending_confirmations(created.id)
    assert len(pending) == 1
    assert pending[0]["task_id"] == created.id


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
