"""G3 reminder-pump forwarding checks."""

from __future__ import annotations

import asyncio
from datetime import datetime
from types import SimpleNamespace
from typing import Any

import pytest

from shisad.daemon.runner import _reminder_delivery_pump
from shisad.scheduler.schema import Schedule, TaskRunRequest


class _SchedulerStub:
    def __init__(
        self,
        *,
        shutdown_event: asyncio.Event,
        run: TaskRunRequest,
        task: Any | None,
    ) -> None:
        self._shutdown_event = shutdown_event
        self._run = run
        self._task = task
        self._trigger_calls = 0

    def trigger_due(self, *, now: datetime | None = None) -> list[TaskRunRequest]:
        _ = now
        self._trigger_calls += 1
        if self._trigger_calls == 1:
            self._shutdown_event.set()
            return [self._run]
        return []

    def get_task(self, task_id: str) -> Any | None:
        if self._task is None:
            return None
        if task_id == self._task.id:
            return self._task
        return None


class _ImplStub:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    async def do_task_execute_due_run(
        self,
        run: TaskRunRequest,
        *,
        event_type: str,
    ) -> dict[str, Any]:
        self.calls.append((run.task_id, event_type))
        return {"accepted": True}


@pytest.mark.asyncio
async def test_reminder_delivery_pump_forwards_due_runs_to_background_executor() -> None:
    shutdown_event = asyncio.Event()
    task = SimpleNamespace(id="task-1", schedule=Schedule(kind="interval", expression="1s"))
    run = TaskRunRequest(
        task_id=task.id,
        trigger_payload="scheduled",
        payload_taint="trusted_scheduler",
        plan_commitment="hash",
    )
    impl = _ImplStub()
    services = SimpleNamespace(
        shutdown_event=shutdown_event,
        scheduler=_SchedulerStub(
            shutdown_event=shutdown_event,
            run=run,
            task=task,
        ),
    )
    handlers = SimpleNamespace(_impl=impl)

    await _reminder_delivery_pump(services=services, handlers=handlers)

    assert impl.calls == [("task-1", "schedule.interval")]


@pytest.mark.asyncio
async def test_reminder_delivery_pump_skips_due_runs_for_missing_tasks() -> None:
    shutdown_event = asyncio.Event()
    run = TaskRunRequest(
        task_id="missing-task",
        trigger_payload="scheduled",
        payload_taint="trusted_scheduler",
        plan_commitment="hash",
    )
    impl = _ImplStub()
    services = SimpleNamespace(
        shutdown_event=shutdown_event,
        scheduler=_SchedulerStub(
            shutdown_event=shutdown_event,
            run=run,
            task=None,
        ),
    )
    handlers = SimpleNamespace(_impl=impl)

    await _reminder_delivery_pump(services=services, handlers=handlers)

    assert impl.calls == []
