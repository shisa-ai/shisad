"""G1 phase-orchestration coverage for do_session_message."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import pytest

from shisad.core.planner import PlannerOutput, PlannerResult
from shisad.core.session import Session
from shisad.core.types import SessionId, SessionMode, SessionState, UserId, WorkspaceId
from shisad.daemon.handlers._impl_session import (
    SessionImplMixin,
    SessionMessageExecutionResult,
    SessionMessagePlannerContextResult,
    SessionMessagePlannerDispatchResult,
    SessionMessageValidationResult,
    TaskDelegationRecommendation,
)
from shisad.security.firewall import FirewallResult
from shisad.security.pep import PolicyContext


def _validation_result(
    *,
    params: Mapping[str, Any],
    early_response: dict[str, Any] | None = None,
) -> SessionMessageValidationResult:
    session = Session(
        id=SessionId("sess-g1"),
        channel="cli",
        user_id=UserId("user-g1"),
        workspace_id=WorkspaceId("workspace-g1"),
        state=SessionState.ACTIVE,
        mode=SessionMode.DEFAULT,
    )
    return SessionMessageValidationResult(
        params=params,
        sid=session.id,
        content=str(params.get("content", "")),
        session=session,
        session_mode=SessionMode.DEFAULT,
        channel="cli",
        user_id=session.user_id,
        workspace_id=session.workspace_id,
        trust_level="trusted",
        trusted_input=True,
        firewall_result=FirewallResult(
            sanitized_text=str(params.get("content", "")),
            original_hash="0" * 64,
        ),
        incoming_taint_labels=set(),
        is_internal_ingress=False,
        early_response=early_response,
    )


class _PhaseHarness(SessionImplMixin):
    def __init__(self) -> None:
        self.calls: list[str] = []

    async def _validate_and_load_session(
        self, params: Mapping[str, Any]
    ) -> SessionMessageValidationResult:
        self.calls.append("validate")
        return _validation_result(params=params)

    async def _build_context_for_planner(
        self, validated: SessionMessageValidationResult
    ) -> SessionMessagePlannerContextResult:
        self.calls.append("build_context")
        assert isinstance(validated, SessionMessageValidationResult)
        return SessionMessagePlannerContextResult(
            validated=validated,
            conversation_context="",
            transcript_context_taints=set(),
            effective_caps=set(),
            memory_query="",
            memory_context="",
            memory_context_taints=set(),
            memory_context_tainted_for_amv=False,
            user_goal_host_patterns=set(),
            untrusted_current_turn="",
            untrusted_host_patterns=set(),
            policy_egress_host_patterns=set(),
            context=PolicyContext(),
            planner_origin="planner-origin",
            committed_plan_hash="plan-g1",
            active_plan_hash="plan-g1",
            planner_tools_payload=[],
            planner_input="planner input",
            assistant_tone_override=None,
        )

    async def _dispatch_to_planner(
        self, planner_context: SessionMessagePlannerContextResult
    ) -> SessionMessagePlannerDispatchResult:
        self.calls.append("dispatch")
        assert isinstance(planner_context, SessionMessagePlannerContextResult)
        return SessionMessagePlannerDispatchResult(
            planner_context=planner_context,
            planner_result=PlannerResult(
                output=PlannerOutput(actions=[], assistant_response="planner response"),
                evaluated=[],
                attempts=1,
                provider_response=None,
                messages_sent=(),
            ),
            planner_failure_code="",
            trace_t0=0.0,
            delegation_advisory=TaskDelegationRecommendation(
                delegate=False,
                action_count=0,
                reason_codes=(),
                tools=(),
            ),
            trace_tool_calls=[],
        )

    async def _evaluate_and_execute_actions(
        self, planner_dispatch: SessionMessagePlannerDispatchResult
    ) -> SessionMessageExecutionResult:
        self.calls.append("execute")
        assert isinstance(planner_dispatch, SessionMessagePlannerDispatchResult)
        return SessionMessageExecutionResult(
            planner_dispatch=planner_dispatch,
            rejected=0,
            pending_confirmation=0,
            executed=0,
            rejection_reasons_for_user=[],
            checkpoint_ids=[],
            pending_confirmation_ids=[],
            executed_tool_outputs=[],
            cleanroom_proposals=[],
            cleanroom_block_reasons=[],
            trace_tool_calls=[],
        )

    async def _finalize_response(
        self, execution: SessionMessageExecutionResult
    ) -> dict[str, Any]:
        self.calls.append("finalize")
        assert isinstance(execution, SessionMessageExecutionResult)
        return {
            "session_id": "sess-g1",
            "response": "ok",
        }


class _EarlyReturnHarness(SessionImplMixin):
    def __init__(self) -> None:
        self.calls: list[str] = []

    async def _validate_and_load_session(
        self, params: Mapping[str, Any]
    ) -> SessionMessageValidationResult:
        self.calls.append("validate")
        return _validation_result(
            params=params,
            early_response={"session_id": "sess-g1", "response": "blocked"},
        )

    async def _build_context_for_planner(self, validated: object) -> object:
        raise AssertionError("phase 2 should not run after an early validation response")

    async def _dispatch_to_planner(self, planner_context: object) -> object:
        raise AssertionError("phase 3 should not run after an early validation response")

    async def _evaluate_and_execute_actions(self, planner_dispatch: object) -> object:
        raise AssertionError("phase 4 should not run after an early validation response")

    async def _finalize_response(self, execution: object) -> dict[str, Any]:
        raise AssertionError("phase 5 should not run after an early validation response")


@pytest.mark.asyncio
async def test_g1_do_session_message_runs_new_phase_methods_in_order() -> None:
    harness = _PhaseHarness()

    result = await SessionImplMixin.do_session_message(
        harness,
        {"session_id": "sess-g1", "content": "hello"},
    )  # type: ignore[arg-type]

    assert harness.calls == [
        "validate",
        "build_context",
        "dispatch",
        "execute",
        "finalize",
    ]
    assert result == {"session_id": "sess-g1", "response": "ok"}


@pytest.mark.asyncio
async def test_g1_do_session_message_short_circuits_on_phase1_early_response() -> None:
    harness = _EarlyReturnHarness()

    result = await SessionImplMixin.do_session_message(
        harness,
        {"session_id": "sess-g1", "content": "hello"},
    )  # type: ignore[arg-type]

    assert harness.calls == ["validate"]
    assert result == {"session_id": "sess-g1", "response": "blocked"}
