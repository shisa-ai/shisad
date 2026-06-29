"""Unit checks for structured plan-step state."""

from __future__ import annotations

import pytest

from shisad.core.api.schema import PlanStepsParams
from shisad.core.plan_steps import PlanStepStore
from shisad.core.types import SessionId
from shisad.daemon.context import RequestContext
from shisad.daemon.handlers._impl_plan_steps import PlanStepsImplMixin
from shisad.daemon.handlers.plan_steps import PlanHandlers


def test_t1_plan_step_store_records_structured_transitions() -> None:
    store = PlanStepStore()
    step_id = store.start_plan_step(
        session_id=SessionId("session-1"),
        plan_hash="plan-1",
        title="Current request",
    )

    rows = store.list_steps(session_id=SessionId("session-1"))

    assert rows[0]["id"] == step_id
    assert rows[0]["plan_hash"] == "plan-1"
    assert rows[0]["order"] == 1
    assert rows[0]["title"] == "Current request"
    assert rows[0]["status"] == "in_progress"
    assert rows[0]["current"] is True

    store.update_step(
        session_id=SessionId("session-1"),
        step_id=step_id,
        status="blocked",
        blocked_reason="pending_confirmation",
    )
    blocked = store.list_steps(session_id=SessionId("session-1"))[0]
    assert blocked["status"] == "blocked"
    assert blocked["current"] is True
    assert blocked["blocked_reason"] == "pending_confirmation"

    store.update_step(session_id=SessionId("session-1"), step_id=step_id, status="done")
    done = store.list_steps(session_id=SessionId("session-1"))[0]
    assert done["status"] == "done"
    assert done["current"] is False


def test_t1_plan_step_store_sorts_structured_rows_and_normalizes_unknown_status() -> None:
    store = PlanStepStore()
    store.replace_steps(
        session_id=SessionId("session-1"),
        steps=[
            {
                "id": "step-2",
                "order": 2,
                "title": "Second",
                "status": "blocked",
                "current": True,
                "depends_on": ["step-1"],
            },
            {
                "id": "step-1",
                "order": 1,
                "title": "First",
                "status": "made_up",
                "current": True,
            },
        ],
    )

    rows = store.list_steps(session_id=SessionId("session-1"))

    assert [row["id"] for row in rows] == ["step-1", "step-2"]
    assert rows[0]["status"] == "unknown"
    assert rows[0]["current"] is False
    assert rows[1]["depends_on"] == ["step-1"]


def test_t1_plan_step_store_active_view_filters_terminal_and_cleared_sessions() -> None:
    store = PlanStepStore()
    done_step = store.start_plan_step(
        session_id=SessionId("session-done"),
        plan_hash="plan-done",
    )
    active_step = store.start_plan_step(
        session_id=SessionId("session-active"),
        plan_hash="plan-active",
    )

    store.update_step(
        session_id=SessionId("session-done"),
        step_id=done_step,
        status="done",
    )

    active_rows = store.list_steps(active_only=True)
    assert [row["id"] for row in active_rows] == [active_step]
    assert store.list_steps(session_id=SessionId("session-done"), active_only=True) == []
    assert store.list_steps(session_id=SessionId("session-done"))[0]["status"] == "done"

    store.clear_session(session_id=SessionId("session-active"))

    assert store.list_steps(session_id=SessionId("session-active")) == []
    assert store.list_steps(active_only=True) == []


@pytest.mark.asyncio
async def test_t1_plan_steps_impl_returns_active_plan_rows_only() -> None:
    class _Impl(PlanStepsImplMixin):
        def __init__(self) -> None:
            self._plan_steps = PlanStepStore()

    impl = _Impl()
    done_step = impl._plan_steps.start_plan_step(
        session_id=SessionId("session-done"),
        plan_hash="plan-done",
    )
    active_step = impl._plan_steps.start_plan_step(
        session_id=SessionId("session-active"),
        plan_hash="plan-active",
    )
    impl._plan_steps.update_step(
        session_id=SessionId("session-done"),
        step_id=done_step,
        status="done",
    )

    result = await impl.do_plan_steps({"limit": 20})

    assert [row["id"] for row in result["steps"]] == [active_step]


@pytest.mark.asyncio
async def test_t1_plan_steps_handler_returns_typed_rows() -> None:
    class _Impl:
        def __init__(self) -> None:
            self.payloads: list[dict[str, object]] = []

        async def do_plan_steps(self, payload: dict[str, object]) -> dict[str, object]:
            self.payloads.append(payload)
            return {
                "session_id": str(payload.get("session_id", "")),
                "steps": [
                    {
                        "id": "step-1",
                        "session_id": str(payload.get("session_id", "")),
                        "order": 1,
                        "title": "Current request",
                        "status": "in_progress",
                        "current": True,
                    }
                ],
                "count": 1,
            }

    marker = object()
    impl = _Impl()
    handlers = PlanHandlers(impl, internal_ingress_marker=marker)  # type: ignore[arg-type]

    result = await handlers.handle_plan_steps(
        PlanStepsParams(session_id="session-1"),
        RequestContext(is_internal_ingress=True),
    )

    assert result.session_id == "session-1"
    assert result.count == 1
    assert result.steps[0].status == "in_progress"
    assert impl.payloads[0]["session_id"] == "session-1"
    assert impl.payloads[0]["_internal_ingress_marker"] is marker
