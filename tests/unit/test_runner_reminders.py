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
        runs: list[TaskRunRequest],
        tasks: dict[str, Any],
    ) -> None:
        self._shutdown_event = shutdown_event
        self._runs = list(runs)
        self._tasks = dict(tasks)
        self._trigger_calls = 0

    def trigger_due(self, *, now: datetime | None = None) -> list[TaskRunRequest]:
        _ = now
        self._trigger_calls += 1
        if self._trigger_calls == 1:
            self._shutdown_event.set()
            return list(self._runs)
        return []

    def get_task(self, task_id: str) -> Any | None:
        return self._tasks.get(task_id)


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


class _FailingImplStub(_ImplStub):
    def __init__(self, *, failing_task_id: str) -> None:
        super().__init__()
        self._failing_task_id = failing_task_id

    async def do_task_execute_due_run(
        self,
        run: TaskRunRequest,
        *,
        event_type: str,
    ) -> dict[str, Any]:
        if run.task_id == self._failing_task_id:
            raise RuntimeError("boom")
        return await super().do_task_execute_due_run(run, event_type=event_type)


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
            runs=[run],
            tasks={task.id: task},
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
            runs=[run],
            tasks={},
        ),
    )
    handlers = SimpleNamespace(_impl=impl)

    await _reminder_delivery_pump(services=services, handlers=handlers)

    assert impl.calls == []


@pytest.mark.asyncio
async def test_reminder_delivery_pump_logs_and_continues_after_per_run_exception() -> None:
    shutdown_event = asyncio.Event()
    first = SimpleNamespace(id="task-1", schedule=Schedule(kind="interval", expression="1s"))
    second = SimpleNamespace(id="task-2", schedule=Schedule(kind="cron", expression="* * * * *"))
    impl = _FailingImplStub(failing_task_id="task-1")
    services = SimpleNamespace(
        shutdown_event=shutdown_event,
        scheduler=_SchedulerStub(
            shutdown_event=shutdown_event,
            runs=[
                TaskRunRequest(
                    task_id=first.id,
                    trigger_payload="scheduled",
                    payload_taint="trusted_scheduler",
                    plan_commitment="hash-1",
                ),
                TaskRunRequest(
                    task_id=second.id,
                    trigger_payload="scheduled",
                    payload_taint="trusted_scheduler",
                    plan_commitment="hash-2",
                ),
            ],
            tasks={first.id: first, second.id: second},
        ),
    )
    handlers = SimpleNamespace(_impl=impl)

    await _reminder_delivery_pump(services=services, handlers=handlers)

    assert impl.calls == [("task-2", "schedule.cron")]
