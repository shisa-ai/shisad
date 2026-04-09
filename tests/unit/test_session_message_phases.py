"""G1 phase-orchestration coverage for do_session_message."""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import Mapping
from types import SimpleNamespace
from typing import Any

import pytest

from shisad.core.evidence import EvidenceStore, KmsArtifactBlobCodec
from shisad.core.planner import (
    ActionProposal,
    EvaluatedProposal,
    PlannerOutput,
    PlannerResult,
)
from shisad.core.session import Session
from shisad.core.tools.registry import ToolRegistry
from shisad.core.tools.schema import ToolDefinition, ToolParameter
from shisad.core.types import (
    Capability,
    PEPDecision,
    PEPDecisionKind,
    SessionId,
    SessionMode,
    SessionState,
    TaintLabel,
    ToolName,
    UserId,
    WorkspaceId,
)
from shisad.daemon.handlers._impl_session import (
    SessionImplMixin,
    SessionMessageExecutionResult,
    SessionMessagePlannerContextResult,
    SessionMessagePlannerDispatchResult,
    SessionMessageValidationResult,
    TaskDelegationRecommendation,
)
from shisad.security.control_plane.schema import ActionKind, ControlDecision, RiskTier
from shisad.security.firewall import FirewallResult
from shisad.security.monitor import MonitorDecisionType
from shisad.security.pep import PEP, PolicyContext
from shisad.security.policy import PolicyBundle
from tests.helpers.artifact_kms import StubArtifactKmsService


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

    async def _finalize_response(self, execution: SessionMessageExecutionResult) -> dict[str, Any]:
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


class _PendingPolicySnapshotHarness(SessionImplMixin):
    def __init__(self) -> None:
        self.captured_merged_policy: object | None = None
        self._event_bus = SimpleNamespace(publish=self._noop_publish)
        self._session_manager = SimpleNamespace(
            get=lambda sid: SimpleNamespace(id=sid),
        )
        self._monitor = SimpleNamespace(
            evaluate=lambda **_kwargs: SimpleNamespace(
                kind=MonitorDecisionType.APPROVE,
                reason="",
            )
        )
        self._monitor_reject_counts: dict[str, int] = {}
        self._registry = SimpleNamespace(
            get_tool=lambda _tool_name: ToolDefinition(
                name=ToolName("shell.exec"),
                description="shell",
            )
        )
        self._control_plane = SimpleNamespace(evaluate_action=self._evaluate_action)
        self._lockdown_manager = SimpleNamespace(should_block_all_actions=lambda _sid: False)
        self._rate_limiter = SimpleNamespace(
            evaluate=lambda **_kwargs: SimpleNamespace(
                block=False,
                require_confirmation=False,
                reason="",
            )
        )
        self._risk_calibrator = SimpleNamespace(record=lambda _observation: None)
        self._trace_recorder = None
        self._pep = SimpleNamespace(
            evaluate=lambda _tool_name, _arguments, _context: PEPDecision(
                kind=PEPDecisionKind.REQUIRE_CONFIRMATION,
                reason="needs confirmation",
                tool_name=ToolName("shell.exec"),
                risk_score=0.5,
            )
        )
        self._policy_loader = SimpleNamespace(
            policy=SimpleNamespace(
                risk_policy=SimpleNamespace(
                    auto_approve_threshold=0.2,
                    block_threshold=0.8,
                )
            )
        )

    async def _noop_publish(self, _event: object) -> None:
        return None

    async def _evaluate_action(self, **_kwargs: object) -> object:
        return SimpleNamespace(
            decision=ControlDecision.ALLOW,
            reason_codes=["trace:stage2_upgrade_required"],
            trace_result=SimpleNamespace(
                allowed=True,
                reason_code="",
                risk_tier=RiskTier.MEDIUM,
            ),
            consensus=SimpleNamespace(votes=[]),
            action=SimpleNamespace(
                action_kind=ActionKind.SHELL_EXEC,
                resource_id="shell.exec",
                resource_ids=[],
                origin=SimpleNamespace(model_dump=lambda mode="json": {}),
            ),
        )

    async def _publish_control_plane_evaluation(self, **_kwargs: object) -> None:
        return None

    def _session_has_tainted_user_history(self, _sid: SessionId) -> bool:
        return False

    async def _record_monitor_reject(self, _sid: SessionId, _reason: str) -> None:
        return None

    async def _record_plan_violation(
        self,
        *,
        sid: SessionId,
        tool_name: ToolName,
        action_kind: ActionKind,
        reason_code: str,
        risk_tier: RiskTier,
    ) -> None:
        _ = (sid, tool_name, action_kind, reason_code, risk_tier)
        return None

    def _build_merged_policy(self, **_kwargs: object) -> object:
        return SimpleNamespace(snapshot="queue-time")

    def _queue_pending_action(self, **kwargs: object) -> object:
        self.captured_merged_policy = kwargs.get("merged_policy")
        return SimpleNamespace(confirmation_id="c-1", reason="requires_confirmation")

    async def _prepare_browser_tool_arguments(
        self,
        *,
        session: object,
        tool_name: ToolName,
        arguments: dict[str, object],
    ) -> dict[str, object]:
        _ = (session, tool_name)
        return dict(arguments)


@pytest.mark.asyncio
async def test_m1_planner_confirmation_persists_queue_time_merged_policy_snapshot() -> None:
    harness = _PendingPolicySnapshotHarness()
    validated = _validation_result(params={"session_id": "sess-g1", "content": "run shell"})
    planner_context = SessionMessagePlannerContextResult(
        validated=validated,
        conversation_context="",
        transcript_context_taints=set(),
        effective_caps={Capability.SHELL_EXEC},
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
    proposal = ActionProposal(
        action_id="a-1",
        tool_name=ToolName("shell.exec"),
        arguments={"command": ["echo", "ok"]},
        reasoning="Run the operator-requested command.",
        data_sources=[],
    )
    planner_dispatch = SessionMessagePlannerDispatchResult(
        planner_context=planner_context,
        planner_result=PlannerResult(
            output=PlannerOutput(assistant_response="Need confirmation.", actions=[proposal]),
            evaluated=[
                EvaluatedProposal(
                    proposal=proposal,
                    decision=PEPDecision(
                        kind=PEPDecisionKind.REQUIRE_CONFIRMATION,
                        reason="needs confirmation",
                        tool_name=proposal.tool_name,
                        risk_score=0.5,
                    ),
                )
            ],
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

    result = await SessionImplMixin._evaluate_and_execute_actions(
        harness,
        planner_dispatch,
    )

    assert result.pending_confirmation == 1
    assert harness.captured_merged_policy is not None
    assert getattr(harness.captured_merged_policy, "snapshot", "") == "queue-time"


class _DispatchRewriteHarness(SessionImplMixin):
    def __init__(self) -> None:
        self._trace_recorder = None
        self._event_bus = SimpleNamespace(publish=self._noop_publish)
        self._planner = SimpleNamespace(propose=self._propose)
        self._pep = SimpleNamespace(evaluate=self._evaluate)

    async def _noop_publish(self, _event: object) -> None:
        return None

    async def _propose(self, *_args: object, **_kwargs: object) -> PlannerResult:
        return PlannerResult(
            output=PlannerOutput(actions=[], assistant_response=""),
            evaluated=[],
            attempts=1,
            provider_response=None,
            messages_sent=(),
        )

    def _evaluate(
        self,
        tool_name: ToolName,
        _arguments: dict[str, object],
        _context: object,
    ) -> object:
        return PEPDecision(
            kind=PEPDecisionKind.ALLOW,
            reason="allow",
            tool_name=tool_name,
            risk_score=0.0,
        )


@pytest.mark.asyncio
async def test_m1_dispatch_to_planner_uses_sanitized_text_for_intent_rewrite() -> None:
    harness = _DispatchRewriteHarness()
    validated = _validation_result(
        params={"session_id": "sess-g1", "content": "add todo: raw-secret"}
    )
    validated.firewall_result = FirewallResult(
        sanitized_text="add todo: safe-title",
        original_hash="0" * 64,
    )
    planner_context = SessionMessagePlannerContextResult(
        validated=validated,
        conversation_context="",
        transcript_context_taints=set(),
        effective_caps={Capability.MEMORY_WRITE},
        memory_query="",
        memory_context="",
        memory_context_taints=set(),
        memory_context_tainted_for_amv=False,
        user_goal_host_patterns=set(),
        untrusted_current_turn="",
        untrusted_host_patterns=set(),
        policy_egress_host_patterns=set(),
        context=PolicyContext(capabilities={Capability.MEMORY_WRITE}),
        planner_origin="planner-origin",
        committed_plan_hash="plan-g1",
        active_plan_hash="plan-g1",
        planner_tools_payload=[],
        planner_input="planner input",
        assistant_tone_override=None,
    )

    dispatch = await SessionImplMixin._dispatch_to_planner(harness, planner_context)

    assert len(dispatch.planner_result.evaluated) == 1
    proposal = dispatch.planner_result.evaluated[0].proposal
    assert proposal.tool_name == ToolName("todo.create")
    assert proposal.arguments == {"title": "safe-title"}


def _finalize_execution_result(*, tool_outputs: list[Any]) -> SessionMessageExecutionResult:
    validated = _validation_result(params={"session_id": "sess-g1", "content": "hello"})
    planner_context = SessionMessagePlannerContextResult(
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
    planner_dispatch = SessionMessagePlannerDispatchResult(
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
    return SessionMessageExecutionResult(
        planner_dispatch=planner_dispatch,
        rejected=0,
        pending_confirmation=0,
        executed=len(tool_outputs),
        rejection_reasons_for_user=[],
        checkpoint_ids=[],
        pending_confirmation_ids=[],
        executed_tool_outputs=tool_outputs,
        cleanroom_proposals=[],
        cleanroom_block_reasons=[],
        trace_tool_calls=[],
    )


class _FinalizeEvidenceHarness(SessionImplMixin):
    def __init__(self) -> None:
        self._evidence_store = object()
        self._firewall = object()
        self._event_bus = SimpleNamespace(publish=self._noop_publish)
        self._output_firewall = SimpleNamespace(
            inspect=lambda text, context: SimpleNamespace(
                blocked=False,
                sanitized_text=text,
                require_confirmation=False,
                model_dump=lambda mode="json": {
                    "blocked": False,
                    "require_confirmation": False,
                    "sanitized_text": text,
                },
            )
        )
        self._lockdown_manager = SimpleNamespace(
            user_notification=lambda _sid: "",
            state_for=lambda _sid: SimpleNamespace(level=SimpleNamespace(value="none")),
        )
        self._transcript_store = SimpleNamespace(append=lambda *args, **kwargs: None)
        self._transcript_root = "/tmp/shisad-test"
        self._trace_recorder = None
        self._planner_model_id = "planner"

    async def _noop_publish(self, _event: object) -> None:
        return None

    async def _send_chat_approval_link_notifications(self, **kwargs) -> None:
        _ = kwargs

    async def _maybe_run_conversation_summarizer(self, **kwargs) -> None:
        _ = kwargs


@pytest.mark.asyncio
async def test_finalize_response_offloads_evidence_wrapping_from_event_loop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _slow_wrap(*, session_id, records, evidence_store, firewall):  # type: ignore[no-untyped-def]
        _ = (session_id, records, evidence_store, firewall)
        time.sleep(0.25)
        return ["ev-slow"]

    monkeypatch.setattr(
        "shisad.daemon.handlers._impl_session._wrap_serialized_tool_outputs_with_evidence",
        _slow_wrap,
    )
    harness = _FinalizeEvidenceHarness()
    execution = _finalize_execution_result(
        tool_outputs=[
            SimpleNamespace(
                tool_name="web.fetch",
                success=True,
                content=json.dumps(
                    {
                        "ok": True,
                        "url": "https://example.com/article",
                        "content": "A" * 400,
                    }
                ),
                taint_labels={TaintLabel.UNTRUSTED},
            )
        ]
    )

    sleep_task = asyncio.create_task(asyncio.sleep(0.05))
    finalize_task = asyncio.create_task(SessionImplMixin._finalize_response(harness, execution))

    done, pending = await asyncio.wait(
        {sleep_task, finalize_task},
        timeout=0.15,
        return_when=asyncio.FIRST_COMPLETED,
    )

    assert sleep_task in done
    assert finalize_task in pending

    response = await finalize_task
    assert response["session_id"] == "sess-g1"


@pytest.mark.asyncio
async def test_evaluate_and_execute_actions_does_not_block_event_loop_during_evidence_pep_check(
    tmp_path,
) -> None:
    sid = SessionId("sess-g1")
    service = StubArtifactKmsService(
        key_material=b"a" * 32,
        request_delay_seconds=0.25,
    )
    with service.run() as endpoint_url:
        store = EvidenceStore(
            tmp_path / "evidence",
            salt=b"a" * 32,
            blob_codec=KmsArtifactBlobCodec(endpoint_url=endpoint_url),
        )
        ref = store.store(
            sid,
            "hello",
            taint_labels={TaintLabel.UNTRUSTED},
            source="web.fetch:example.com",
            summary="hello",
        )
        request_count = len(service.requests)
        registry = ToolRegistry()
        registry.register(
            ToolDefinition(
                name=ToolName("evidence.promote"),
                description="promote evidence",
                parameters=[ToolParameter(name="ref_id", type="string", required=True)],
                capabilities_required=[Capability.MEMORY_READ],
            )
        )
        pep = PEP(
            PolicyBundle(default_require_confirmation=False),
            registry,
            evidence_store=store,
        )
        harness = _PendingPolicySnapshotHarness()
        harness._registry = registry
        harness._pep = pep

        async def _slow_evaluate_action(**_kwargs: object) -> object:
            await asyncio.sleep(0.25)
            return SimpleNamespace(
                decision=ControlDecision.ALLOW,
                reason_codes=[],
                trace_result=SimpleNamespace(
                    allowed=True,
                    reason_code="",
                    risk_tier=RiskTier.MEDIUM,
                ),
                consensus=SimpleNamespace(votes=[]),
                action=SimpleNamespace(
                    action_kind=ActionKind.MEMORY_WRITE,
                    resource_id="evidence.promote",
                    resource_ids=[],
                    origin=SimpleNamespace(model_dump=lambda mode="json": {}),
                ),
            )

        harness._control_plane = SimpleNamespace(evaluate_action=_slow_evaluate_action)

        planner_context = SessionMessagePlannerContextResult(
            validated=_validation_result(params={"session_id": str(sid), "content": "promote"}),
            conversation_context="",
            transcript_context_taints=set(),
            effective_caps={Capability.MEMORY_READ},
            memory_query="",
            memory_context="",
            memory_context_taints=set(),
            memory_context_tainted_for_amv=False,
            user_goal_host_patterns=set(),
            untrusted_current_turn="",
            untrusted_host_patterns=set(),
            policy_egress_host_patterns=set(),
            context=PolicyContext(capabilities={Capability.MEMORY_READ}, session_id=sid),
            planner_origin="planner-origin",
            committed_plan_hash="plan-g1",
            active_plan_hash="plan-g1",
            planner_tools_payload=[],
            planner_input="planner input",
            assistant_tone_override=None,
        )
        proposal = ActionProposal(
            action_id="a-1",
            tool_name=ToolName("evidence.promote"),
            arguments={"ref_id": ref.ref_id},
            reasoning="Promote evidence.",
            data_sources=[],
        )
        planner_dispatch = SessionMessagePlannerDispatchResult(
            planner_context=planner_context,
            planner_result=PlannerResult(
                output=PlannerOutput(assistant_response="Need confirmation.", actions=[proposal]),
                evaluated=[
                    EvaluatedProposal(
                        proposal=proposal,
                        decision=PEPDecision(
                            kind=PEPDecisionKind.REQUIRE_CONFIRMATION,
                            reason="needs confirmation",
                            tool_name=proposal.tool_name,
                            risk_score=0.5,
                        ),
                    )
                ],
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

        sleep_task = asyncio.create_task(asyncio.sleep(0.05))
        execute_task = asyncio.create_task(
            SessionImplMixin._evaluate_and_execute_actions(harness, planner_dispatch)
        )

        done, pending = await asyncio.wait(
            {sleep_task, execute_task},
            timeout=0.15,
            return_when=asyncio.FIRST_COMPLETED,
        )

        assert sleep_task in done
        assert execute_task in pending

        result = await execute_task

    assert result.pending_confirmation == 1
    assert len(service.requests) == request_count
