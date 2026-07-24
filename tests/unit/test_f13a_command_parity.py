"""F13A COMMAND parity and bounded-provenance contract tests."""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any

import pytest

import shisad.daemon.handlers._impl_session as impl_session
from shisad.core.planner import (
    BASE_SYSTEM_PROMPT,
    ActionProposal,
    EvaluatedProposal,
    Planner,
    PlannerOutput,
    PlannerOutputError,
    PlannerResult,
)
from shisad.core.providers.base import Message, ProviderResponse
from shisad.core.providers.capabilities import ProviderCapabilities
from shisad.core.tools.registry import ToolRegistry
from shisad.core.tools.schema import (
    ToolDefinition,
    ToolParameter,
    openai_function_name,
    tool_definitions_to_openai,
)
from shisad.core.types import (
    PEPDecision,
    PEPDecisionKind,
    SessionId,
    SessionMode,
    TaintLabel,
    ToolName,
    UserId,
    WorkspaceId,
)
from shisad.daemon.handlers._impl_session import SessionMessageValidationResult
from shisad.security.firewall import FirewallResult
from shisad.security.pep import PEP, PolicyContext
from shisad.security.policy import PolicyBundle

_CURRENT_TURN_TOOL_CALL_SOURCE = "planner:current_turn_tool_call"
_POSTURES = ("native", "content")
_TOOL_CASES = (
    ("thread.list", {}),
    ("note.create", {"content": "remember to buy groceries"}),
    ("note.search", {"query": "groceries"}),
    ("todo.create", {"title": "review PRs"}),
    ("reminder.create", {"message": "check email", "when": "in 5 seconds"}),
    (
        "fs.read",
        {
            "path": "README.md",
            "max_bytes": 1048576,
            "filesystem_intent": "current_turn_local_read",
        },
    ),
    ("web.search", {"query": "agent security", "limit": 5}),
    ("browser.navigate", {"url": "https://example.com/guide"}),
    ("evidence.read", {"ref_id": "ev_test_123"}),
)


class _StaticProvider:
    def __init__(self, responses: list[Message]) -> None:
        self._responses = responses
        self.calls = 0

    async def complete(
        self,
        messages: list[Message],
        tools: list[dict[str, Any]] | None = None,
    ) -> ProviderResponse:
        del messages, tools
        index = min(self.calls, len(self._responses) - 1)
        self.calls += 1
        return ProviderResponse(message=self._responses[index], finish_reason="stop")


def _registry() -> ToolRegistry:
    registry = ToolRegistry()
    definitions = (
        ("thread.list", ()),
        ("note.create", (("content", "string", True),)),
        ("note.search", (("query", "string", True),)),
        ("todo.create", (("title", "string", True),)),
        (
            "reminder.create",
            (("message", "string", True), ("when", "string", True)),
        ),
        (
            "fs.read",
            (
                ("path", "string", True),
                ("max_bytes", "integer", False),
                ("filesystem_intent", "string", False),
            ),
        ),
        (
            "web.search",
            (("query", "string", True), ("limit", "integer", False)),
        ),
        ("browser.navigate", (("url", "string", True),)),
        ("evidence.read", (("ref_id", "string", True),)),
    )
    for name, parameters in definitions:
        registry.register(
            ToolDefinition(
                name=ToolName(name),
                description=f"Exercise {name}.",
                parameters=[
                    ToolParameter(name=field, type=kind, required=required)
                    for field, kind, required in parameters
                ],
            )
        )
    return registry


def _provider_message(
    posture: str,
    calls: list[tuple[str, dict[str, Any]]],
) -> Message:
    payloads = [
        {
            "name": openai_function_name(name),
            "arguments": arguments,
        }
        for name, arguments in calls
    ]
    if posture == "content":
        return Message(role="assistant", content=json.dumps(payloads))
    return Message(
        role="assistant",
        tool_calls=[
            {
                "id": f"call-{index}",
                "type": "function",
                "function": {
                    "name": payload["name"],
                    "arguments": json.dumps(payload["arguments"]),
                },
            }
            for index, payload in enumerate(payloads, start=1)
        ],
    )


def _planner(
    posture: str,
    responses: list[Message],
    *,
    max_retries: int = 0,
) -> tuple[Planner, _StaticProvider, list[dict[str, Any]]]:
    registry = _registry()
    provider = _StaticProvider(responses)
    planner = Planner(
        provider,
        PEP(PolicyBundle(default_require_confirmation=False), registry),
        max_retries=max_retries,
        capabilities=ProviderCapabilities(
            supports_tool_calls=posture == "native",
            supports_content_tool_calls=posture == "content",
        ),
        tool_registry=registry,
        schema_strict_mode=True,
    )
    return planner, provider, tool_definitions_to_openai(registry.list_tools())


def _evaluated(proposal: ActionProposal) -> EvaluatedProposal:
    return EvaluatedProposal(
        proposal=proposal,
        decision=PEPDecision(
            kind=PEPDecisionKind.ALLOW,
            reason="allow",
            tool_name=proposal.tool_name,
            risk_score=0.0,
        ),
    )


def _validated_turn(
    text: str,
    *,
    channel: str = "cli",
    session_mode: SessionMode = SessionMode.DEFAULT,
    trust_level: str = "trusted",
    trusted_input: bool = True,
    operator_owned_cli_input: bool = True,
    incoming_taint_labels: set[TaintLabel] | None = None,
    is_internal_ingress: bool = False,
    risk_score: float = 0.0,
) -> SessionMessageValidationResult:
    return SessionMessageValidationResult(
        sid=SessionId("sess-f13a"),
        params={"content": text},
        content=text,
        session=SimpleNamespace(),
        session_mode=session_mode,
        channel=channel,
        user_id=UserId("user-f13a"),
        workspace_id=WorkspaceId("workspace-f13a"),
        trust_level=trust_level,
        trusted_input=trusted_input,
        firewall_result=FirewallResult(
            sanitized_text=text,
            original_hash="0" * 64,
            risk_score=risk_score,
            risk_factors=["prompt_injection"] if risk_score else [],
        ),
        incoming_taint_labels=set(incoming_taint_labels or set()),
        is_internal_ingress=is_internal_ingress,
        operator_owned_cli_input=operator_owned_cli_input,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("posture", _POSTURES)
@pytest.mark.parametrize(("tool_name", "arguments"), _TOOL_CASES)
async def test_f13a_command_family_matrix_has_canonical_current_turn_source(
    posture: str,
    tool_name: str,
    arguments: dict[str, Any],
) -> None:
    planner, _provider, tools = _planner(
        posture,
        [_provider_message(posture, [(tool_name, arguments)])],
    )

    result = await planner.propose("current user request", PolicyContext(), tools=tools)

    assert [
        (str(item.proposal.tool_name), item.proposal.arguments) for item in result.evaluated
    ] == [(tool_name, arguments)]
    assert result.output.actions[0].data_sources == [_CURRENT_TURN_TOOL_CALL_SOURCE]


@pytest.mark.asyncio
async def test_f13a_native_call_rejects_registered_tool_omitted_from_manifest() -> None:
    planner, provider, tools = _planner(
        "native",
        [_provider_message("native", [("note.create", {"content": "hidden"})])],
    )
    current_manifest = [
        item for item in tools if item["function"]["name"] == openai_function_name("thread.list")
    ]

    with pytest.raises(PlannerOutputError, match="strict schema validation"):
        await planner.propose("list threads", PolicyContext(), tools=current_manifest)

    assert provider.calls == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("posture", _POSTURES)
async def test_f13a_command_multi_call_preserves_order_source_and_pep(
    posture: str,
) -> None:
    calls = [
        (
            "fs.read",
            {
                "path": "README.md",
                "max_bytes": 1048576,
                "filesystem_intent": "current_turn_local_read",
            },
        ),
        ("web.search", {"query": "related projects", "limit": 5}),
    ]
    planner, _provider, tools = _planner(posture, [_provider_message(posture, calls)])

    result = await planner.propose("read and search", PolicyContext(), tools=tools)

    assert [
        (str(item.proposal.tool_name), item.proposal.arguments) for item in result.evaluated
    ] == calls
    assert [item.data_sources for item in result.output.actions] == [
        [_CURRENT_TURN_TOOL_CALL_SOURCE],
        [_CURRENT_TURN_TOOL_CALL_SOURCE],
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize("posture", _POSTURES)
async def test_f13a_invalid_output_retries_then_returns_valid_typed_call(
    posture: str,
) -> None:
    invalid = _provider_message(posture, [("note.create", {})])
    valid = _provider_message(
        posture,
        [("note.create", {"content": "remember to buy groceries"})],
    )
    planner, provider, tools = _planner(posture, [invalid, valid], max_retries=1)

    result = await planner.propose("remember groceries", PolicyContext(), tools=tools)

    assert provider.calls == 2
    assert result.attempts == 2
    assert result.output.actions[0].data_sources == [_CURRENT_TURN_TOOL_CALL_SOURCE]


@pytest.mark.asyncio
@pytest.mark.parametrize("posture", _POSTURES)
async def test_f13a_invalid_output_exhaustion_remains_explicit(posture: str) -> None:
    planner, provider, tools = _planner(
        posture,
        [_provider_message(posture, [("note.create", {})])],
        max_retries=1,
    )

    with pytest.raises(PlannerOutputError, match="strict schema validation"):
        await planner.propose("remember groceries", PolicyContext(), tools=tools)

    assert provider.calls == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("posture", _POSTURES)
async def test_f13a_unrelated_speech_stays_conversational(posture: str) -> None:
    planner, _provider, tools = _planner(
        posture,
        [Message(role="assistant", content="Hello! How can I help?")],
    )

    result = await planner.propose("hello", PolicyContext(), tools=tools)

    assert result.output.actions == []
    assert result.evaluated == []
    assert result.output.assistant_response == "Hello! How can I help?"


def test_f13a_command_prompt_names_full_tool_posture_and_general_multi_action() -> None:
    normalized = " ".join(BASE_SYSTEM_PROMPT.casefold().split())

    assert "thread, note and memory, todo, reminder, filesystem, web, browser, and evidence" in (
        normalized
    )
    assert "multiple independent actions" in normalized


def test_f13a_exact_command_proposal_is_not_replaced_for_private_label_absence() -> None:
    registry = _registry()
    pep = PEP(PolicyBundle(default_require_confirmation=False), registry)
    proposal = ActionProposal(
        action_id="call-note",
        tool_name=ToolName("note.create"),
        arguments={"content": "remember to buy groceries"},
        reasoning="Use the typed note tool.",
        data_sources=[_CURRENT_TURN_TOOL_CALL_SOURCE],
    )
    planner_result = PlannerResult(
        output=PlannerOutput(
            assistant_response="Creating the note.",
            actions=[proposal],
        ),
        evaluated=[_evaluated(proposal)],
        attempts=1,
    )

    rewritten = impl_session._rewrite_explicit_memory_intent_planner_result(
        user_text="add a note: remember to buy groceries",
        planner_result=planner_result,
        pep=pep,
        context=PolicyContext(),
    )

    assert rewritten is planner_result


@pytest.mark.parametrize(
    (
        "tool_name",
        "arguments",
        "sources",
        "validated",
        "expected",
    ),
    [
        (
            "note.create",
            {"content": "remember to buy groceries"},
            [_CURRENT_TURN_TOOL_CALL_SOURCE],
            _validated_turn("add a note: remember to buy groceries"),
            True,
        ),
        (
            "todo.create",
            {"title": "review PRs"},
            [_CURRENT_TURN_TOOL_CALL_SOURCE],
            _validated_turn("add todo: review PRs"),
            True,
        ),
        (
            "note.create",
            {"content": "hallucinated secret"},
            [_CURRENT_TURN_TOOL_CALL_SOURCE],
            _validated_turn("add a note: remember to buy groceries"),
            False,
        ),
        (
            "fs.write",
            {"path": "notes.txt", "content": "hello"},
            [_CURRENT_TURN_TOOL_CALL_SOURCE],
            _validated_turn("write hello to notes.txt"),
            False,
        ),
        (
            "note.create",
            {"content": "remember to buy groceries"},
            [_CURRENT_TURN_TOOL_CALL_SOURCE],
            _validated_turn(
                "add a note: remember to buy groceries",
                channel="discord",
                trust_level="untrusted",
                trusted_input=False,
                operator_owned_cli_input=False,
            ),
            False,
        ),
        (
            "note.create",
            {"content": "remember to buy groceries"},
            [_CURRENT_TURN_TOOL_CALL_SOURCE],
            _validated_turn(
                "add a note: remember to buy groceries",
                is_internal_ingress=True,
                operator_owned_cli_input=False,
            ),
            False,
        ),
        (
            "note.create",
            {"content": "remember to buy groceries"},
            [_CURRENT_TURN_TOOL_CALL_SOURCE],
            _validated_turn(
                "add a note: remember to buy groceries",
                incoming_taint_labels={TaintLabel.UNTRUSTED},
            ),
            False,
        ),
        (
            "note.create",
            {"content": "remember to buy groceries"},
            [_CURRENT_TURN_TOOL_CALL_SOURCE],
            _validated_turn(
                "add a note: remember to buy groceries",
                risk_score=0.8,
            ),
            False,
        ),
        (
            "note.create",
            {"content": "remember to buy groceries"},
            [_CURRENT_TURN_TOOL_CALL_SOURCE],
            _validated_turn(
                "add a note: remember to buy groceries",
                session_mode=SessionMode.TASK,
            ),
            False,
        ),
        (
            "note.create",
            {"content": "legacy parser value"},
            ["user_text:explicit_memory_intent"],
            _validated_turn(
                "untrusted baseline posture",
                channel="discord",
                trust_level="untrusted",
                trusted_input=False,
                operator_owned_cli_input=False,
            ),
            True,
        ),
    ],
    ids=(
        "note-clean-anchored",
        "todo-clean-anchored",
        "note-unanchored",
        "filesystem-not-memory",
        "public-channel",
        "internal-ingress",
        "tainted-turn",
        "firewall-risk",
        "task-mode",
        "legacy-source-preserved",
    ),
)
def test_f13a_current_turn_source_grants_only_bounded_memory_authority(
    tool_name: str,
    arguments: dict[str, Any],
    sources: list[str],
    validated: SessionMessageValidationResult,
    expected: bool,
) -> None:
    helper = getattr(
        impl_session,
        "_proposal_has_current_turn_memory_write_authority",
        None,
    )
    assert callable(helper)
    proposal = ActionProposal(
        action_id="call-memory",
        tool_name=ToolName(tool_name),
        arguments=arguments,
        reasoning="Use a typed runtime tool.",
        data_sources=sources,
    )

    assert helper(proposal=proposal, validated=validated) is expected


def test_f13a_compatibility_action_preserves_local_fallback_truth() -> None:
    registry = _registry()
    pep = PEP(PolicyBundle(default_require_confirmation=False), registry)
    fallback_message = "Planner route is unavailable; configure a provider."
    planner_result = PlannerResult(
        output=PlannerOutput(actions=[], assistant_response=fallback_message),
        evaluated=[],
        attempts=1,
        provider_response=ProviderResponse(
            message=Message(role="assistant", content=fallback_message),
            trusted_origin="local-fallback",
        ),
    )

    rewritten = impl_session._rewrite_explicit_memory_intent_planner_result(
        user_text="add a note: remember to buy groceries",
        planner_result=planner_result,
        pep=pep,
        context=PolicyContext(),
    )

    assert [str(item.proposal.tool_name) for item in rewritten.evaluated] == ["note.create"]
    assert rewritten.output.assistant_response == fallback_message


def test_f13a_fallback_prefix_shifts_protected_tool_output_bounds() -> None:
    notice = "[PLANNER FALLBACK: configured planner route was unavailable]"
    assistant_text = "I can use shell.exec for that. Could you clarify?"
    tool_output = (
        "Completed action result:\n"
        "- fs.read: output says I can use shell.exec inside direct file content."
    )
    response_text = f"{assistant_text}\n\n{tool_output}"
    protected_start = response_text.index(tool_output)
    helper = getattr(
        impl_session,
        "_prepend_trusted_local_fallback_notice",
        None,
    )
    assert callable(helper)

    prefixed, shifted_start, shifted_end = helper(
        response_text=response_text,
        notice=notice,
        protected_tool_output_start=protected_start,
        protected_tool_output_end=len(response_text),
    )

    shift = len(notice) + 2
    assert shifted_start == protected_start + shift
    assert shifted_end == len(response_text) + shift
    coerced = impl_session._coerce_blocked_action_response_text(
        response_text=prefixed,
        rejected=1,
        pending_confirmation=0,
        executed_tool_outputs=1,
        rejection_reasons=["action_monitor:side_effect_on_tainted_session"],
        rejected_tool_names=["shell.exec"],
        protected_tool_output_start=shifted_start,
        protected_tool_output_end=shifted_end,
    )
    assert notice in coerced
    assert "Could you clarify?" not in coerced
    assert "inside direct file content." in coerced
