"""Unit checks for task handler wrappers."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from shisad.channels.base import DeliveryTarget
from shisad.core.api.schema import (
    NoParams,
    TaskCreateParams,
    TaskDisableParams,
    TaskPendingConfirmationsParams,
    TaskStatusSnapshotParams,
    TaskTriggerEventParams,
)
from shisad.core.events import ToolRejected
from shisad.core.types import Capability, PEPDecisionKind, SessionId, UserId, WorkspaceId
from shisad.daemon.context import RequestContext
from shisad.daemon.handlers._impl_tasks import TasksImplMixin
from shisad.daemon.handlers.tasks import TaskHandlers
from shisad.security.pep import PolicyContext


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
            "status_snapshot": [],
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

    async def do_task_status_snapshot(self, payload: dict[str, object]) -> dict[str, object]:
        self.payloads.append(("status_snapshot", payload))
        return self._next(
            "status_snapshot",
            {
                "tasks": [
                    {
                        "task_id": "task-1",
                        "title": "task one",
                        "status": "enabled",
                        "schedule_kind": "event",
                        "schedule_summary": "event-triggered: alarm",
                    }
                ],
                "count": 1,
                "user_id": str(payload.get("user_id", "")),
                "workspace_id": str(payload.get("workspace_id", "")),
                "scope_status": "scoped",
            },
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


class _QueueTaskConfirmationHarness(TasksImplMixin):
    def __init__(self) -> None:
        self.pending_kwargs: list[dict[str, object]] = []
        self.scheduler_confirmations: list[tuple[str, dict[str, object]]] = []
        self.published_events: list[object] = []
        self._scheduler = SimpleNamespace(queue_confirmation=self._queue_confirmation)
        self._event_bus = SimpleNamespace(publish=self._publish_event)

    async def _publish_event(self, event: object) -> None:
        self.published_events.append(event)

    def _queue_confirmation(self, task_id: str, action: dict[str, object]) -> None:
        self.scheduler_confirmations.append((task_id, action))

    def _queue_pending_action(self, **kwargs: object) -> object:
        self.pending_kwargs.append(kwargs)
        return SimpleNamespace(
            confirmation_id="confirm-task-1",
            action_id="act-task-1",
            origin_turn_id=str(kwargs.get("origin_turn_id", "")),
            session_id=kwargs.get("session_id", SessionId("scheduler-session-1")),
            user_id=kwargs.get("user_id", UserId("alice")),
            workspace_id=kwargs.get("workspace_id", WorkspaceId("ws1")),
            task_id=str(kwargs.get("task_id", "")),
            delivery_target=kwargs.get("delivery_target"),
            execution_attempt_id="",
            result_id="",
            followup_id="followup-task-1",
            approval_task_envelope_id="",
            decision_nonce="nonce-task-1",
            confirmation_evidence=None,
            status="pending",
            status_reason="",
            created_at="",
            expires_at=None,
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
async def test_a1_queue_task_confirmation_carries_task_delivery_target() -> None:
    harness = _QueueTaskConfirmationHarness()
    task = SimpleNamespace(
        id="task-1",
        created_by="alice",
        workspace_id="ws1",
        delivery_target={
            "channel": "discord",
            "recipient": "chan-1",
            "workspace_hint": "guild-1",
            "thread_id": "thread-1",
        },
    )
    run = SimpleNamespace(
        payload_taint="trusted_scheduler",
        trigger_payload="wake",
        plan_commitment="plan-1",
    )
    session = SimpleNamespace(id=SessionId("scheduler-session-1"))

    confirmation_id = await harness._queue_task_confirmation(
        task=task,
        run=run,
        event_type="message.received",
        session=session,
        arguments={"channel": "discord", "recipient": "chan-1", "body": "hello"},
        reason="requires_confirmation",
        capabilities={Capability.MESSAGE_SEND},
        preflight_action=None,
        pep_context=PolicyContext(
            capabilities={Capability.MESSAGE_SEND},
            trust_level="internal",
        ),
    )

    assert confirmation_id == "confirm-task-1"
    assert len(harness.pending_kwargs) == 1
    delivery_target = harness.pending_kwargs[0]["delivery_target"]
    assert isinstance(delivery_target, DeliveryTarget)
    assert delivery_target.channel == "discord"
    assert delivery_target.recipient == "chan-1"
    assert delivery_target.workspace_hint == "guild-1"
    assert delivery_target.thread_id == "thread-1"
    assert harness.scheduler_confirmations[0][0] == "task-1"
    queued_event = next(
        event
        for event in harness.published_events
        if isinstance(event, ToolRejected)
        and event.decision == PEPDecisionKind.REQUIRE_CONFIRMATION
    )
    assert queued_event.action_id == "act-task-1"
    assert queued_event.origin_turn_id.startswith("task-run:")
    assert queued_event.followup_id == "followup-task-1"
    assert queued_event.approval_session_id == "scheduler-session-1"
    assert queued_event.approval_task_envelope_id == ""
    assert queued_event.approval_confirmation_id == "confirm-task-1"
    assert queued_event.user_id == "alice"
    assert queued_event.workspace_id == "ws1"
    assert queued_event.task_id == "task-1"
    assert queued_event.delivery_target == {
        "channel": "discord",
        "recipient": "chan-1",
        "thread_id": "thread-1",
        "workspace_hint": "guild-1",
    }
    assert queued_event.execution_attempt_id == ""
    assert queued_event.result_id == ""
    assert queued_event.approval_decision_nonce == ""


@pytest.mark.asyncio
async def test_task_list_validates_count_shape() -> None:
    impl = _ProgrammableImpl()
    handlers = _handlers(impl)
    listing = await handlers.handle_task_list(NoParams(), RequestContext())
    assert listing.count == 1


@pytest.mark.asyncio
async def test_t2_task_status_snapshot_ignores_caller_supplied_scope() -> None:
    impl = _ProgrammableImpl()
    handlers = _handlers(impl)

    snapshot = await handlers.handle_task_status_snapshot(
        TaskStatusSnapshotParams(
            session_id="session-operator",
            user_id="mallory",
            workspace_id="other-workspace",
            limit=5,
        ),
        RequestContext(),
    )

    assert snapshot.count == 1
    assert snapshot.tasks[0].task_id == "task-1"
    assert impl.payloads[-1] == (
        "status_snapshot",
        {"session_id": "session-operator", "limit": 5},
    )


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
