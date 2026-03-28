"""Regression tests for task implementation normalization paths."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from shisad.daemon.handlers._impl_tasks import TasksImplMixin
from shisad.scheduler.manager import SchedulerManager


class _EventCollector:
    def __init__(self) -> None:
        self.events: list[object] = []

    async def publish(self, event: object) -> None:
        self.events.append(event)


class _TaskImplHarness(TasksImplMixin):
    def __init__(self, storage_dir: Path) -> None:
        self._scheduler = SchedulerManager(storage_dir=storage_dir)
        self._event_bus = _EventCollector()


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
