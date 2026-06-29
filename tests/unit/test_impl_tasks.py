"""Regression tests for task implementation normalization paths."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from shisad.core.types import UserId, WorkspaceId
from shisad.daemon.handlers._impl_tasks import TasksImplMixin
from shisad.scheduler.manager import SchedulerManager
from shisad.scheduler.schema import Schedule


class _EventCollector:
    def __init__(self) -> None:
        self.events: list[object] = []

    async def publish(self, event: object) -> None:
        self.events.append(event)


class _TaskImplHarness(TasksImplMixin):
    def __init__(self, storage_dir: Path) -> None:
        self._scheduler = SchedulerManager(storage_dir=storage_dir)
        self._event_bus = _EventCollector()


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
async def test_t2_do_task_status_snapshot_scopes_and_redacts_pending_rows() -> None:
    scheduler = _ScopedSnapshotScheduler()
    harness = SimpleNamespace(_scheduler=scheduler)

    payload = await TasksImplMixin.do_task_status_snapshot(
        harness,  # type: ignore[arg-type]
        {"user_id": "alice", "workspace_id": "ws1", "limit": 5},
    )

    assert scheduler.snapshot_calls == [
        {"limit": 5, "created_by": "alice", "workspace_id": "ws1"}
    ]
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
            "task_id": "task-visible",
            "tool_name": "message.send",
            "event_type": "message.received",
            "payload_taint": "UNTRUSTED",
            "reason": "requires_confirmation",
            "status": "pending",
            "queued_at": "2026-06-29T00:00:00+00:00",
        }
    ]
    assert "trigger_payload" not in row["pending_confirmations"][0]


@pytest.mark.asyncio
async def test_t2_do_task_status_snapshot_requires_complete_scope() -> None:
    scheduler = _ScopedSnapshotScheduler()
    harness = SimpleNamespace(_scheduler=scheduler)

    payload = await TasksImplMixin.do_task_status_snapshot(
        harness,  # type: ignore[arg-type]
        {"user_id": "alice", "workspace_id": "", "limit": 5},
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
