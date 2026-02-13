"""Unit checks for task handler wrappers."""

from __future__ import annotations

import pytest

from shisad.core.api.schema import (
    NoParams,
    TaskCreateParams,
    TaskPendingConfirmationsParams,
    TaskTriggerEventParams,
)
from shisad.daemon.context import RequestContext
from shisad.daemon.handlers.tasks import TaskHandlers


class _StubImpl:
    async def do_task_create(self, payload: dict[str, object]) -> dict[str, object]:
        return {"id": "task-1", "name": str(payload["name"])}

    async def do_task_list(self, _payload: dict[str, object]) -> dict[str, object]:
        return {"tasks": [{"id": "task-1"}], "count": 1}

    async def do_task_disable(self, payload: dict[str, object]) -> dict[str, object]:
        return {"disabled": True, "task_id": str(payload["task_id"])}

    async def do_task_trigger_event(self, _payload: dict[str, object]) -> dict[str, object]:
        return {"runs": [{"task_id": "task-1"}], "count": 1, "queued_confirmations": 1}

    async def do_task_pending_confirmations(
        self, payload: dict[str, object]
    ) -> dict[str, object]:
        return {"task_id": str(payload["task_id"]), "pending": [], "count": 0}


@pytest.mark.asyncio
async def test_task_create_and_list_wrappers() -> None:
    handlers = TaskHandlers(_StubImpl(), internal_ingress_marker=object())  # type: ignore[arg-type]
    created = await handlers.handle_task_create(
        TaskCreateParams(
            schedule={"cron": "* * * * *"},
            name="scan",
            goal="scan logs",
            policy_snapshot_ref="policy-1",
            created_by="alice",
        ),
        RequestContext(),
    )
    listing = await handlers.handle_task_list(NoParams(), RequestContext())
    assert created.model_dump(mode="json")["id"] == "task-1"
    assert listing.count == 1


@pytest.mark.asyncio
async def test_task_trigger_and_pending_wrappers() -> None:
    handlers = TaskHandlers(_StubImpl(), internal_ingress_marker=object())  # type: ignore[arg-type]
    triggered = await handlers.handle_task_trigger_event(
        TaskTriggerEventParams(event_type="alarm", payload="x"),
        RequestContext(),
    )
    pending = await handlers.handle_task_pending_confirmations(
        TaskPendingConfirmationsParams(task_id="task-1"),
        RequestContext(),
    )
    assert triggered.queued_confirmations == 1
    assert pending.task_id == "task-1"
