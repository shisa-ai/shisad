"""Regression tests for task implementation normalization paths."""

from __future__ import annotations

import asyncio
from pathlib import Path
from threading import Event, Thread
from types import SimpleNamespace

import pytest

from shisad.core.events import ToolRejected
from shisad.core.evidence import ArtifactLedger
from shisad.core.tools.registry import ToolRegistry
from shisad.core.tools.schema import ToolDefinition, ToolParameter
from shisad.core.types import (
    Capability,
    SessionId,
    SessionMode,
    SessionRole,
    SessionState,
    ToolName,
    UserId,
    WorkspaceId,
)
from shisad.daemon.handlers._impl_tasks import TasksImplMixin
from shisad.scheduler.manager import SchedulerManager
from shisad.scheduler.schema import Schedule
from shisad.security.control_plane.schema import ControlDecision
from shisad.security.pep import PEP
from shisad.security.policy import PolicyBundle


class _EventCollector:
    def __init__(self) -> None:
        self.events: list[object] = []

    async def publish(self, event: object) -> None:
        self.events.append(event)


class _TaskImplHarness(TasksImplMixin):
    def __init__(self, storage_dir: Path) -> None:
        self._scheduler = SchedulerManager(storage_dir=storage_dir)
        self._event_bus = _EventCollector()


class _TaskLifecycleSerializationHarness(TasksImplMixin):
    def __init__(self) -> None:
        self.started = asyncio.Event()
        self.release = asyncio.Event()
        self.sequence: list[str] = []
        self._scheduler = SimpleNamespace(disable_task=self._disable_task)

    def _disable_task(self, task_id: str) -> bool:
        self.sequence.append(f"disable:{task_id}")
        return True

    async def _execute_task_run_locked(
        self,
        run: object,
        *,
        event_type: str,
        due_run: bool,
    ) -> dict[str, object]:
        self.sequence.append(f"execute:{getattr(run, 'task_id', '')}:{event_type}:{due_run}")
        self.started.set()
        await self.release.wait()
        self.sequence.append("execute:done")
        return {"accepted": True, "queued_confirmation": True, "executed": False}

    async def _cancel_pending_actions_for_task(self, task_id: str, *, reason: str) -> list[str]:
        self.sequence.append(f"cancel:{task_id}:{reason}")
        return ["confirm-1"]


class _ScopedSnapshotScheduler:
    def __init__(self) -> None:
        self.snapshot_calls: list[dict[str, object]] = []
        self.pending_calls: list[str] = []

    def task_status_snapshot(
        self,
        *,
        limit: int,
        created_by: UserId | None = None,
        workspace_id: WorkspaceId | None = None,
    ) -> list[dict[str, object]]:
        self.snapshot_calls.append(
            {
                "limit": limit,
                "created_by": str(created_by or ""),
                "workspace_id": str(workspace_id or ""),
            }
        )
        return [
            {
                "task_id": "task-visible",
                "title": "visible task",
                "status": "enabled",
                "schedule_kind": "event",
                "schedule_summary": "event-triggered: message.received",
                "delivery_channel": "discord",
                "created_by": str(created_by or ""),
                "workspace_id": str(workspace_id or ""),
            }
        ]

    def pending_confirmations(self, task_id: str) -> list[dict[str, object]]:
        self.pending_calls.append(task_id)
        return [
            {
                "confirmation_id": "confirm-visible",
                "task_id": task_id,
                "tool_name": "message.send",
                "event_type": "message.received",
                "trigger_payload": "do not render this raw payload",
                "payload_taint": "UNTRUSTED",
                "reason": "requires_confirmation",
                "status": "pending",
                "queued_at": "2026-06-29T00:00:00+00:00",
            }
        ]


class _ActiveSessionRegistry:
    def __init__(self, *sessions: SimpleNamespace) -> None:
        self._sessions = list(sessions)

    def get(self, session_id: SessionId) -> SimpleNamespace | None:
        for session in self._sessions:
            if str(session.id) == str(session_id):
                return session
        return None


def _operator_session(
    session_id: str,
    user_id: str,
    workspace_id: str,
    *,
    peer_uid: int = 1000,
) -> SimpleNamespace:
    return SimpleNamespace(
        id=SessionId(session_id),
        user_id=UserId(user_id),
        workspace_id=WorkspaceId(workspace_id),
        channel="cli",
        state=SessionState.ACTIVE,
        role=SessionRole.ORCHESTRATOR,
        mode=SessionMode.DEFAULT,
        metadata={
            "operator_owned_cli": True,
            "created_rpc_peer": {"uid": peer_uid, "pid": 1234, "gid": peer_uid},
        },
    )


def _task_session(session_id: str, user_id: str, workspace_id: str) -> SimpleNamespace:
    return SimpleNamespace(
        id=SessionId(session_id),
        user_id=UserId(user_id),
        workspace_id=WorkspaceId(workspace_id),
        channel="task",
        state=SessionState.ACTIVE,
        role=SessionRole.SUBAGENT,
        mode=SessionMode.TASK,
        metadata={
            "operator_owned_cli": False,
            "created_rpc_peer": {"uid": 1000, "pid": 1234, "gid": 1000},
        },
    )


class _TaskStatusSnapshotHarness(TasksImplMixin):
    def __init__(
        self,
        scheduler: _ScopedSnapshotScheduler,
        session_manager: _ActiveSessionRegistry,
    ) -> None:
        self._scheduler = scheduler
        self._session_manager = session_manager


def test_m1_task_delivery_arguments_normalize_none_optional_strings() -> None:
    task = SimpleNamespace(
        delivery_target={
            "channel": "discord",
            "recipient": "ops-room",
            "workspace_hint": None,
            "thread_id": None,
        },
        goal="Reminder: standup",
    )

    arguments = TasksImplMixin._task_delivery_arguments(task)

    assert arguments == {
        "channel": "discord",
        "recipient": "ops-room",
        "message": "Reminder: standup",
    }


@pytest.mark.asyncio
async def test_m1_do_task_create_normalizes_none_delivery_target_values(tmp_path: Path) -> None:
    harness = _TaskImplHarness(tmp_path / "scheduler")

    payload = await TasksImplMixin.do_task_create(
        harness,
        {
            "schedule": {"kind": "interval", "expression": "5s"},
            "name": "reminder:standup",
            "goal": "Reminder: standup",
            "capability_snapshot": [],
            "policy_snapshot_ref": "planner:reminder.create",
            "created_by": "user-1",
            "workspace_id": "ws-1",
            "delivery_target": {
                "channel": "discord",
                "recipient": "ops-room",
                "workspace_hint": None,
                "thread_id": None,
            },
            "max_runs": 1,
        },
    )

    assert payload["delivery_target"] == {
        "channel": "discord",
        "recipient": "ops-room",
    }


@pytest.mark.asyncio
async def test_f1_reject_task_run_audits_complete_scheduled_scope(tmp_path: Path) -> None:
    harness = _TaskImplHarness(tmp_path / "scheduler")
    task = harness._scheduler.create_task(
        name="reminder:standup",
        goal="Reminder: standup",
        schedule=Schedule(kind="interval", expression="5m"),
        capability_snapshot=set(),
        policy_snapshot_ref="planner:reminder.create",
        created_by=UserId("alice"),
        workspace_id=WorkspaceId("ws1"),
        delivery_target={
            "channel": "discord",
            "recipient": "ops-room",
            "workspace_hint": "guild-1",
            "thread_id": "thread-1",
        },
    )

    result = await TasksImplMixin._reject_task_run(
        harness,  # type: ignore[arg-type]
        sid=SessionId("scheduler-session-1"),
        task=task,
        reason="session_in_lockdown",
    )

    assert result == {"accepted": False, "queued_confirmation": False, "executed": False}
    rejected = next(event for event in harness._event_bus.events if isinstance(event, ToolRejected))
    assert rejected.user_id == "alice"
    assert rejected.workspace_id == "ws1"
    assert rejected.task_id == task.id
    assert rejected.delivery_target == {
        "channel": "discord",
        "recipient": "ops-room",
        "workspace_hint": "guild-1",
        "thread_id": "thread-1",
    }


@pytest.mark.asyncio
async def test_f1_task_disable_serializes_after_inflight_task_run() -> None:
    harness = _TaskLifecycleSerializationHarness()
    run_task = asyncio.create_task(
        TasksImplMixin._execute_task_run(
            harness,  # type: ignore[arg-type]
            SimpleNamespace(task_id="task-1"),
            event_type="message.received",
            due_run=False,
        )
    )
    await harness.started.wait()
    disable_task = asyncio.create_task(
        TasksImplMixin.do_task_disable(
            harness,  # type: ignore[arg-type]
            {"task_id": "task-1"},
        )
    )
    await asyncio.sleep(0)
    assert disable_task.done() is False

    harness.release.set()

    assert await run_task == {"accepted": True, "queued_confirmation": True, "executed": False}
    assert await disable_task == {"disabled": True, "task_id": "task-1"}
    assert harness.sequence == [
        "execute:task-1:message.received:False",
        "execute:done",
        "disable:task-1",
        "cancel:task-1:task_disabled",
    ]


@pytest.mark.asyncio
async def test_f3_actual_task_pep_route_keeps_event_loop_live_behind_evidence_writer(
    tmp_path: Path,
) -> None:
    ledger = ArtifactLedger(tmp_path / "evidence", salt=b"a" * 32)
    registry = ToolRegistry()
    registry.register(
        ToolDefinition(
            name=ToolName("message.send"),
            description="send a message",
            parameters=[
                ToolParameter(name="channel", type="string", required=True),
                ToolParameter(name="recipient", type="string", required=True),
                ToolParameter(name="message", type="string", required=True),
            ],
            capabilities_required=[Capability.MESSAGE_SEND],
        )
    )
    pep = PEP(
        PolicyBundle(default_require_confirmation=False),
        registry,
        evidence_store=ledger,
    )
    task = SimpleNamespace(
        id="task-1",
        enabled=True,
        goal="send the scheduled update",
        delivery_target={"channel": "discord", "recipient": "ops-room"},
        capability_snapshot={Capability.MESSAGE_SEND},
        workspace_id=WorkspaceId("ws-1"),
        created_by=UserId("user-1"),
        task_envelope=None,
        allowed_recipients=[],
        allowed_domains=[],
        commitment_hash=lambda: "commitment-1",
    )
    run = SimpleNamespace(
        task_id="task-1",
        plan_commitment="commitment-1",
        payload_taint="trusted_scheduler",
        trigger_payload="scheduled update",
    )
    control_evaluation = SimpleNamespace(
        trace_result=SimpleNamespace(reason_code=""),
        consensus=SimpleNamespace(votes=[]),
        decision=ControlDecision.ALLOW,
        reason_codes=[],
        action=SimpleNamespace(),
    )

    class _ControlPlane:
        def active_plan_hash(self, _session_id: str) -> str:
            return ""

        def begin_precontent_plan(self, **_kwargs: object) -> str:
            return "plan-task-1"

        def evaluate_action(self, **_kwargs: object) -> object:
            return control_evaluation

    class _ActualTaskPepHarness(TasksImplMixin):
        def __init__(self) -> None:
            self._scheduler = SimpleNamespace(get_task=lambda _task_id: task)
            self._event_bus = _EventCollector()
            self._control_plane = _ControlPlane()
            self._pep = pep
            self._policy_loader = SimpleNamespace(
                policy=SimpleNamespace(
                    control_plane=SimpleNamespace(
                        trace=SimpleNamespace(
                            ttl_seconds=1800,
                            max_actions=10,
                            allow_amendment=True,
                        )
                    )
                )
            )
            self._lockdown_manager = SimpleNamespace(
                apply_capability_restrictions=lambda _sid, capabilities: set(capabilities),
                should_block_all_actions=lambda _sid: True,
            )

        def _ensure_task_execution_session(self, _task: object) -> object:
            return SimpleNamespace(id=SessionId("task-session-1"), channel="scheduler")

        async def _publish_control_plane_evaluation(self, **_kwargs: object) -> None:
            return None

        async def _observe_pep_reject_signal(self, **_kwargs: object) -> None:
            return None

        async def _reject_task_run(self, **_kwargs: object) -> dict[str, bool]:
            return {"accepted": False, "queued_confirmation": False, "executed": False}

    harness = _ActualTaskPepHarness()
    lock_held = Event()
    release_writer = Event()
    holder_timed_out = Event()

    def _hold_writer() -> None:
        with ledger._lock:
            lock_held.set()
            if not release_writer.wait(timeout=3.0):
                holder_timed_out.set()

    holder = Thread(target=_hold_writer)
    holder.start()
    assert await asyncio.to_thread(lock_held.wait, 1.0)
    heartbeat_ticks = 0

    async def _heartbeat() -> None:
        nonlocal heartbeat_ticks
        for _ in range(5):
            heartbeat_ticks += 1
            await asyncio.sleep(0)
        release_writer.set()

    heartbeat = asyncio.create_task(_heartbeat())
    result = await TasksImplMixin._execute_task_run_locked(
        harness,
        run,
        event_type="schedule.due",
        due_run=True,
    )
    await heartbeat
    await asyncio.to_thread(holder.join, 1.0)

    assert holder_timed_out.is_set() is False
    assert heartbeat_ticks == 5
    assert result == {"accepted": False, "queued_confirmation": False, "executed": False}


@pytest.mark.asyncio
async def test_t2_do_task_status_snapshot_binds_to_active_session_scope_and_redacts() -> None:
    scheduler = _ScopedSnapshotScheduler()
    harness = _TaskStatusSnapshotHarness(
        scheduler,
        _ActiveSessionRegistry(_operator_session("operator-session", "alice", "ws1")),
    )

    payload = await TasksImplMixin.do_task_status_snapshot(
        harness,  # type: ignore[arg-type]
        {
            "session_id": "operator-session",
            "user_id": "mallory",
            "workspace_id": "other-workspace",
            "limit": 5,
            "_rpc_peer": {"uid": 1000, "pid": 9999, "gid": 1000},
        },
    )

    assert scheduler.snapshot_calls == [{"limit": 5, "created_by": "alice", "workspace_id": "ws1"}]
    assert scheduler.pending_calls == ["task-visible"]
    assert payload["scope_status"] == "scoped"
    assert payload["count"] == 1
    row = payload["tasks"][0]
    assert row["task_id"] == "task-visible"
    assert row["delivery_channel"] == "discord"
    assert row["confirmation_needed"] is True
    assert row["pending_confirmation_count"] == 1
    assert row["pending_confirmations"] == [
        {
            "confirmation_id": "confirm-visible",
            "action_id": "",
            "execution_attempt_id": "",
            "identity": {},
            "task_id": "task-visible",
            "tool_name": "message.send",
            "event_type": "message.received",
            "payload_taint": "UNTRUSTED",
            "reason": "requires_confirmation",
            "status": "pending",
            "lifecycle_state": "pending",
            "result_id": "",
            "expires_at": "",
            "queued_at": "2026-06-29T00:00:00+00:00",
        }
    ]
    assert "trigger_payload" not in row["pending_confirmations"][0]


@pytest.mark.asyncio
async def test_t2_do_task_status_snapshot_requires_bound_scope() -> None:
    scheduler = _ScopedSnapshotScheduler()
    harness = _TaskStatusSnapshotHarness(
        scheduler,
        _ActiveSessionRegistry(_operator_session("operator-session", "alice", "")),
    )

    payload = await TasksImplMixin.do_task_status_snapshot(
        harness,  # type: ignore[arg-type]
        {"session_id": "operator-session", "limit": 5, "_rpc_peer": {"uid": 1000}},
    )

    assert payload["tasks"] == []
    assert payload["count"] == 0
    assert payload["scope_status"] == "missing_scope"
    assert scheduler.snapshot_calls == []
    assert scheduler.pending_calls == []


@pytest.mark.asyncio
async def test_t2_do_task_status_snapshot_requires_matching_rpc_peer() -> None:
    scheduler = _ScopedSnapshotScheduler()
    harness = _TaskStatusSnapshotHarness(
        scheduler,
        _ActiveSessionRegistry(_operator_session("operator-session", "alice", "ws1")),
    )

    payload = await TasksImplMixin.do_task_status_snapshot(
        harness,  # type: ignore[arg-type]
        {"session_id": "operator-session", "limit": 5, "_rpc_peer": {"uid": 2000}},
    )

    assert payload["tasks"] == []
    assert payload["count"] == 0
    assert payload["scope_status"] == "missing_scope"
    assert scheduler.snapshot_calls == []
    assert scheduler.pending_calls == []


@pytest.mark.asyncio
async def test_t2_do_task_status_snapshot_rejects_task_session_scope() -> None:
    scheduler = _ScopedSnapshotScheduler()
    harness = _TaskStatusSnapshotHarness(
        scheduler,
        _ActiveSessionRegistry(_task_session("task-session", "alice", "ws1")),
    )

    payload = await TasksImplMixin.do_task_status_snapshot(
        harness,  # type: ignore[arg-type]
        {"session_id": "task-session", "limit": 5, "_rpc_peer": {"uid": 1000}},
    )

    assert payload["tasks"] == []
    assert payload["count"] == 0
    assert payload["scope_status"] == "missing_scope"
    assert scheduler.snapshot_calls == []
    assert scheduler.pending_calls == []


def test_t2_scheduler_status_snapshot_includes_safe_delivery_channel() -> None:
    scheduler = SchedulerManager()
    task = scheduler.create_task(
        name="reminder:standup",
        goal="Reminder: standup",
        schedule=Schedule.from_event("message.received"),
        capability_snapshot=set(),
        policy_snapshot_ref="planner:reminder.create",
        created_by=UserId("alice"),
        workspace_id=WorkspaceId("ws1"),
        delivery_target={
            "channel": "discord",
            "recipient": "ops-room",
        },
    )

    rows = scheduler.task_status_snapshot(
        limit=5,
        created_by=UserId("alice"),
        workspace_id=WorkspaceId("ws1"),
    )

    assert rows[0]["task_id"] == task.id
    assert rows[0]["delivery_channel"] == "discord"
    assert "recipient" not in rows[0]
