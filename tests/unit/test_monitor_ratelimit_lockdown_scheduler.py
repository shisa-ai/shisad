"""M2.T9-T12, T21: monitor, rate limits, lockdown, scheduler, and risk policy."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

from shisad.core.types import Capability, SessionId, UserId, WorkspaceId
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


def test_m4_action_monitor_rejects_goal_misaligned_dotted_runtime_tools() -> None:
    monitor = ActionMonitor()
    decision = monitor.evaluate(
        user_goal="summarize this document",
        actions=[
            SimpleNamespace(
                tool_name="shell.exec",
                arguments={"command": ["cat", "/etc/passwd"]},
                reasoning="run a command",
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


def test_g3_scheduler_persists_execution_session_and_filters_resolved_confirmations(
    tmp_path: Path,
) -> None:
    storage = tmp_path / "tasks"
    first = SchedulerManager(storage_dir=storage)
    created = first.create_task(
        name="reminder",
        goal="ping ops",
        schedule=Schedule(kind="interval", expression="60s"),
        capability_snapshot={Capability.MESSAGE_SEND},
        policy_snapshot_ref="p1",
        created_by=UserId("alice"),
        workspace_id=WorkspaceId("ws1"),
    )
    first.attach_execution_session(created.id, "sess-background-1")
    first.queue_confirmation(
        created.id,
        {
            "confirmation_id": "confirm-1",
            "task_id": created.id,
            "status": "pending",
        },
    )
    first.resolve_confirmation(
        created.id,
        confirmation_id="confirm-1",
        status="approved",
        status_reason="manual_confirm",
    )

    restarted = SchedulerManager(storage_dir=storage)
    loaded = restarted.get_task(created.id)
    assert loaded is not None
    assert loaded.execution_session_id == "sess-background-1"
    assert restarted.pending_confirmations(created.id) == []

    rows = restarted.task_status_snapshot(
        limit=8,
        created_by=UserId("alice"),
        workspace_id=WorkspaceId("ws1"),
    )
    assert rows[0]["pending_confirmation_count"] == 0
    assert rows[0]["confirmation_needed"] is False


def test_g3_scheduler_prunes_resolved_confirmation_backlog(tmp_path: Path) -> None:
    storage = tmp_path / "tasks"
    scheduler = SchedulerManager(storage_dir=storage)
    created = scheduler.create_task(
        name="reminder",
        goal="ping ops",
        schedule=Schedule(kind="interval", expression="60s"),
        capability_snapshot={Capability.MESSAGE_SEND},
        policy_snapshot_ref="p1",
        created_by=UserId("alice"),
    )
    for index in range(40):
        confirmation_id = f"confirm-{index}"
        scheduler.queue_confirmation(
            created.id,
            {
                "confirmation_id": confirmation_id,
                "task_id": created.id,
                "status": "pending",
            },
        )
        scheduler.resolve_confirmation(
            created.id,
            confirmation_id=confirmation_id,
            status="approved",
            status_reason="manual_confirm",
        )

    restarted = SchedulerManager(storage_dir=storage)
    assert restarted.pending_confirmations(created.id) == []
    assert len(restarted._pending_confirmations[created.id]) == 32
    remaining_ids = [
        str(row.get("confirmation_id", "")) for row in restarted._pending_confirmations[created.id]
    ]
    assert "confirm-0" not in remaining_ids
    assert "confirm-39" in remaining_ids


def test_m2_scheduler_skips_corrupt_utf8_persisted_files(tmp_path: Path) -> None:
    storage = tmp_path / "tasks"
    storage.mkdir(parents=True, exist_ok=True)
    (storage / "tasks.json").write_bytes(b"\xff")
    (storage / "pending_confirmations.json").write_bytes(b"\xff")

    restarted = SchedulerManager(storage_dir=storage)
    assert restarted.list_tasks() == []
    assert restarted.pending_confirmations("missing-task") == []


def test_m2_scheduler_interval_due_runs_once_per_interval() -> None:
    scheduler = SchedulerManager()
    task = scheduler.create_task(
        name="reminder",
        goal="standup",
        schedule=Schedule(kind="interval", expression="60s"),
        capability_snapshot={Capability.MESSAGE_SEND},
        policy_snapshot_ref="p1",
        created_by=UserId("alice"),
    )
    base = datetime(2026, 2, 15, 10, 0, 0, tzinfo=UTC)
    task.created_at = base

    assert scheduler.trigger_due(now=base) == []
    first = scheduler.trigger_due(now=base + timedelta(seconds=61))
    assert len(first) == 1
    assert first[0].task_id == task.id
    assert first[0].payload_taint == "trusted_scheduler"
    assert scheduler.trigger_due(now=base + timedelta(seconds=90)) == []
    second = scheduler.trigger_due(now=base + timedelta(seconds=122))
    assert len(second) == 1


def test_m2_scheduler_cron_due_runs_once_per_matching_minute() -> None:
    scheduler = SchedulerManager()
    task = scheduler.create_task(
        name="digest",
        goal="daily digest",
        schedule=Schedule(kind="cron", expression="*/5 * * * *"),
        capability_snapshot={Capability.MESSAGE_SEND},
        policy_snapshot_ref="p1",
        created_by=UserId("alice"),
    )
    minute_00 = datetime(2026, 2, 15, 10, 0, 0, tzinfo=UTC)
    task.created_at = minute_00

    first = scheduler.trigger_due(now=minute_00)
    assert len(first) == 1
    assert scheduler.trigger_due(now=minute_00 + timedelta(seconds=30)) == []
    assert scheduler.trigger_due(now=minute_00 + timedelta(minutes=4, seconds=59)) == []
    second = scheduler.trigger_due(now=minute_00 + timedelta(minutes=5))
    assert len(second) == 1


def test_m2_scheduler_cron_step_respects_nonzero_field_minimum() -> None:
    scheduler = SchedulerManager()
    task = scheduler.create_task(
        name="every-other-day",
        goal="check alternating days",
        schedule=Schedule(kind="cron", expression="0 0 */2 * *"),
        capability_snapshot={Capability.MESSAGE_SEND},
        policy_snapshot_ref="p1",
        created_by=UserId("alice"),
    )
    day_01 = datetime(2026, 3, 1, 0, 0, 0, tzinfo=UTC)
    task.created_at = day_01

    assert len(scheduler.trigger_due(now=day_01)) == 1
    assert scheduler.trigger_due(now=day_01 + timedelta(days=1)) == []
    assert len(scheduler.trigger_due(now=day_01 + timedelta(days=2))) == 1


def test_m4_task_status_snapshot_scopes_to_owner_and_workspace() -> None:
    scheduler = SchedulerManager()
    task_alice_ws1 = scheduler.create_task(
        name="alice-ws1",
        goal="task one",
        schedule=Schedule.from_event("message.received"),
        capability_snapshot={Capability.MEMORY_READ},
        policy_snapshot_ref="p1",
        created_by=UserId("alice"),
        workspace_id=WorkspaceId("ws1"),
    )
    _task_alice_ws2 = scheduler.create_task(
        name="alice-ws2",
        goal="task two",
        schedule=Schedule.from_event("message.received"),
        capability_snapshot={Capability.MEMORY_READ},
        policy_snapshot_ref="p1",
        created_by=UserId("alice"),
        workspace_id=WorkspaceId("ws2"),
    )
    _task_bob_ws1 = scheduler.create_task(
        name="bob-ws1",
        goal="task three",
        schedule=Schedule.from_event("message.received"),
        capability_snapshot={Capability.MEMORY_READ},
        policy_snapshot_ref="p1",
        created_by=UserId("bob"),
        workspace_id=WorkspaceId("ws1"),
    )

    rows = scheduler.task_status_snapshot(
        limit=10,
        created_by=UserId("alice"),
        workspace_id=WorkspaceId("ws1"),
    )
    assert len(rows) == 1
    assert rows[0]["task_id"] == task_alice_ws1.id
    assert rows[0]["created_by"] == "alice"
    assert rows[0]["workspace_id"] == "ws1"


def test_m4_task_status_snapshot_excludes_blank_workspace_from_scoped_queries() -> None:
    scheduler = SchedulerManager()
    _blank_workspace = scheduler.create_task(
        name="legacy-global-task",
        goal="task one",
        schedule=Schedule.from_event("message.received"),
        capability_snapshot={Capability.MEMORY_READ},
        policy_snapshot_ref="p1",
        created_by=UserId("alice"),
    )
    task_scoped = scheduler.create_task(
        name="scoped-task",
        goal="task two",
        schedule=Schedule.from_event("message.received"),
        capability_snapshot={Capability.MEMORY_READ},
        policy_snapshot_ref="p1",
        created_by=UserId("alice"),
        workspace_id=WorkspaceId("ws1"),
    )

    rows = scheduler.task_status_snapshot(
        limit=10,
        created_by=UserId("alice"),
        workspace_id=WorkspaceId("ws1"),
    )
    assert len(rows) == 1
    assert rows[0]["task_id"] == task_scoped.id
    assert rows[0]["workspace_id"] == "ws1"


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
