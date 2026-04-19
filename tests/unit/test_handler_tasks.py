"""Unit checks for task handler wrappers."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from shisad.core.api.schema import (
    NoParams,
    TaskCreateParams,
    TaskDisableParams,
    TaskPendingConfirmationsParams,
    TaskTriggerEventParams,
)
from shisad.daemon.context import RequestContext
from shisad.daemon.handlers.tasks import TaskHandlers


class _ProgrammableImpl:
    """Records payloads and returns scripted per-call results or exceptions."""

    def __init__(self) -> None:
        self.payloads: list[tuple[str, dict[str, object]]] = []
        self._scripts: dict[str, list[dict[str, object] | Exception]] = {
            "create": [],
            "list": [],
            "disable": [],
            "trigger": [],
            "pending": [],
        }

    def script(self, kind: str, result: dict[str, object] | Exception) -> None:
        self._scripts[kind].append(result)

    async def do_task_create(self, payload: dict[str, object]) -> dict[str, object]:
        self.payloads.append(("create", payload))
        return self._next("create", {"id": "task-1", "name": str(payload.get("name", ""))})

    async def do_task_list(self, payload: dict[str, object]) -> dict[str, object]:
        self.payloads.append(("list", payload))
        return self._next("list", {"tasks": [{"id": "task-1"}], "count": 1})

    async def do_task_disable(self, payload: dict[str, object]) -> dict[str, object]:
        self.payloads.append(("disable", payload))
        return self._next(
            "disable",
            {"disabled": True, "task_id": str(payload.get("task_id", ""))},
        )

    async def do_task_trigger_event(self, payload: dict[str, object]) -> dict[str, object]:
        self.payloads.append(("trigger", payload))
        return self._next(
            "trigger",
            {"runs": [{"task_id": "task-1"}], "count": 1, "queued_confirmations": 1},
        )

    async def do_task_pending_confirmations(self, payload: dict[str, object]) -> dict[str, object]:
        self.payloads.append(("pending", payload))
        return self._next(
            "pending",
            {"task_id": str(payload.get("task_id", "")), "pending": [], "count": 0},
        )

    def _next(self, kind: str, default: dict[str, object]) -> dict[str, object]:
        queue = self._scripts[kind]
        if not queue:
            return dict(default)
        scripted = queue.pop(0)
        if isinstance(scripted, Exception):
            raise scripted
        return dict(scripted)


def _handlers(impl: _ProgrammableImpl, marker: object | None = None) -> TaskHandlers:
    return TaskHandlers(
        impl,  # type: ignore[arg-type]
        internal_ingress_marker=marker or object(),
    )


@pytest.mark.asyncio
async def test_task_create_forwards_params_and_ingress_marker() -> None:
    impl = _ProgrammableImpl()
    marker = object()
    handlers = _handlers(impl, marker=marker)

    created = await handlers.handle_task_create(
        TaskCreateParams(
            schedule={"cron": "* * * * *"},
            name="scan",
            goal="scan logs",
            policy_snapshot_ref="policy-1",
            created_by="alice",
            workspace_id="ws1",
        ),
        RequestContext(is_internal_ingress=True),
    )

    assert created.id == "task-1"
    assert created.name == "scan"
    kind, payload = impl.payloads[0]
    assert kind == "create"
    assert payload["name"] == "scan"
    assert payload["goal"] == "scan logs"
    assert payload["policy_snapshot_ref"] == "policy-1"
    assert payload["workspace_id"] == "ws1"
    assert payload["_internal_ingress_marker"] is marker


@pytest.mark.asyncio
async def test_task_list_validates_count_shape() -> None:
    impl = _ProgrammableImpl()
    handlers = _handlers(impl)
    listing = await handlers.handle_task_list(NoParams(), RequestContext())
    assert listing.count == 1


@pytest.mark.asyncio
async def test_task_disable_forwards_id_to_impl() -> None:
    impl = _ProgrammableImpl()
    handlers = _handlers(impl)

    disabled = await handlers.handle_task_disable(
        TaskDisableParams(task_id="task-1"),
        RequestContext(),
    )
    assert disabled.disabled is True
    assert disabled.task_id == "task-1"
    assert (
        impl.payloads[-1]
        == (
            "disable",
            {"task_id": "task-1"},
        )
        or impl.payloads[-1][1].get("task_id") == "task-1"
    )


@pytest.mark.asyncio
async def test_task_trigger_and_pending_wrappers() -> None:
    impl = _ProgrammableImpl()
    handlers = _handlers(impl)
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


@pytest.mark.asyncio
async def test_task_create_propagates_validation_and_rejects_missing_id() -> None:
    """HDL-M2: the tautological stub used to be the only reason this test
    passed. Pin that missing-id impl payloads are rejected by Pydantic so a
    regression that silently returned `{}` cannot slip through."""

    impl = _ProgrammableImpl()
    impl.script("create", {"name": "no-id-in-this-payload"})
    handlers = _handlers(impl)

    with pytest.raises(ValidationError, match="id"):
        await handlers.handle_task_create(
            TaskCreateParams(
                schedule={"cron": "* * * * *"},
                name="scan",
                goal="scan logs",
                policy_snapshot_ref="policy-1",
                created_by="alice",
                workspace_id="ws1",
            ),
            RequestContext(),
        )


@pytest.mark.asyncio
async def test_task_trigger_event_propagates_blocked_runs_and_queued_counts() -> None:
    impl = _ProgrammableImpl()
    impl.script(
        "trigger",
        {
            "runs": [{"task_id": "task-1"}, {"task_id": "task-2"}],
            "count": 2,
            "queued_confirmations": 1,
            "blocked_runs": 1,
        },
    )
    handlers = _handlers(impl)

    triggered = await handlers.handle_task_trigger_event(
        TaskTriggerEventParams(event_type="alarm", payload="x"),
        RequestContext(),
    )
    assert triggered.count == 2
    assert triggered.queued_confirmations == 1
    assert triggered.blocked_runs == 1


@pytest.mark.asyncio
async def test_task_handler_bubbles_impl_valueerror() -> None:
    impl = _ProgrammableImpl()
    impl.script("disable", ValueError("unknown task id"))
    handlers = _handlers(impl)

    with pytest.raises(ValueError, match="unknown task id"):
        await handlers.handle_task_disable(
            TaskDisableParams(task_id="task-ghost"),
            RequestContext(),
        )
