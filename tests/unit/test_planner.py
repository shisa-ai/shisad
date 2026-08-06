"""M1 RF-014: planner native tool-calling and safety behavior."""

from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest

from shisad.core.context import ContextScaffold, ContextScaffoldEntry
from shisad.core.context_budget import assess_request_capacity
from shisad.core.planner import Planner, PlannerOutputError
from shisad.core.providers.base import Message, ProviderResponse
from shisad.core.providers.capabilities import ProviderCapabilities
from shisad.core.tools.builtin.shell_exec import ShellExecTool
from shisad.core.tools.registry import ToolRegistry
from shisad.core.tools.schema import ToolDefinition, ToolParameter
from shisad.core.types import Capability, PEPDecision, PEPDecisionKind, TaintLabel, ToolName
from shisad.security.pep import PEP, PolicyContext
from shisad.security.policy import PolicyBundle
from shisad.security.spotlight import build_planner_input_v2


class StaticProvider:
    def __init__(
        self,
        responses: list[Message],
        *,
        trusted_origin: str = "",
    ) -> None:
        self._responses = responses
        self._trusted_origin = trusted_origin
        self.calls = 0
        self.messages: list[list[Message]] = []
        self.tools: list[list[dict[str, Any]] | None] = []

    async def complete(
        self,
        messages: list[Message],
        tools: list[dict[str, Any]] | None = None,
    ) -> ProviderResponse:
        self.messages.append(list(messages))
        self.tools.append(tools)
        index = min(self.calls, len(self._responses) - 1)
        self.calls += 1
        return ProviderResponse(
            message=self._responses[index],
            finish_reason="stop",
            usage={},
            trusted_origin=self._trusted_origin,
        )


class RecordingPEP:
    def __init__(self, pep: PEP) -> None:
        self._pep = pep
        self.calls: list[tuple[ToolName, dict[str, Any]]] = []

    def evaluate(
        self,
        tool_name: ToolName,
        arguments: dict[str, Any],
        context: PolicyContext,
    ) -> PEPDecision:
        self.calls.append((tool_name, arguments))
        return self._pep.evaluate(tool_name, arguments, context)


@pytest.mark.asyncio
async def test_i2_irreducible_context_capacity_fails_before_provider_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from shisad.core.providers.base import ProviderContextCapacityError

    registry = _make_registry()
    pep = PEP(PolicyBundle(default_require_confirmation=False), registry)
    provider = StaticProvider([Message(role="assistant", content="must not be called")])
    planner = Planner(
        provider,
        pep,
        max_retries=2,
        capabilities=ProviderCapabilities(
            context_window_tokens=512,
            output_reserve_tokens=128,
        ),
    )
    tools = [
        {
            "type": "function",
            "function": {
                "name": "echo",
                "description": "required schema sentinel",
                "parameters": {
                    "type": "object",
                    "properties": {"text": {"type": "string"}},
                    "required": ["text"],
                },
            },
        }
    ]
    observed: dict[str, Any] = {}

    def _recording_assessment(**kwargs: Any):
        observed.update(kwargs)
        return assess_request_capacity(**kwargs)

    monkeypatch.setattr("shisad.core.planner.assess_request_capacity", _recording_assessment)
    planner_input = build_planner_input_v2(
        trusted_instructions="required planner safety sentinel",
        user_goal="authenticated current goal sentinel " * 300,
        untrusted_content="",
        scaffold=ContextScaffold(
            session_id="s-i2-r2",
            trusted_frontmatter="trust_level=trusted\nsecurity_frontmatter=retained",
            untrusted_entries=[
                ContextScaffoldEntry(
                    entry_id="current_turn",
                    content="tainted current-turn sentinel",
                    source_taint_labels=[TaintLabel.UNTRUSTED.value],
                )
            ],
        ),
        deterministic=True,
        delimiter_seed="i2-r2",
    )

    with pytest.raises(ProviderContextCapacityError) as caught:
        await planner.propose(
            planner_input,
            PolicyContext(capabilities={Capability.FILE_READ}),
            tools=tools,
        )

    assert provider.calls == 0
    observed_messages = observed["messages"]
    assert observed_messages[0].role == "system"
    assert "NON-NEGOTIABLE SAFETY INSTRUCTIONS" in observed_messages[0].content
    observed_payload = observed_messages[-1].content.replace("^", "")
    assert "required planner safety sentinel" in observed_payload
    assert "authenticated current goal sentinel" in observed_payload
    assert "tainted current-turn sentinel" in observed_payload
    assert "security_frontmatter=retained" in observed_payload
    assert observed["tools"] == tools
    assert caught.value.context_window_tokens == 512
    assert caught.value.estimated_input_tokens > 384
    user_message = caught.value.user_message()
    assert "512-token context window" in user_message
    assert "shorten" in user_message.lower()
    assert "larger-context model" in user_message.lower()
    assert "HTTP 400" not in user_message
    assert "https://" not in user_message


def _i3a_final_answer_call(answer: str, *, call_id: str = "final-1") -> dict[str, Any]:
    return {
        "id": call_id,
        "type": "function",
        "function": {
            "name": "respond_to_user",
            "arguments": json.dumps({"final_answer": answer}),
        },
    }


@pytest.mark.asyncio
async def test_i3a_remote_no_action_response_uses_typed_final_answer() -> None:
    registry = _make_registry()
    pep = RecordingPEP(PEP(PolicyBundle(default_require_confirmation=False), registry))
    provider = StaticProvider(
        [
            Message(
                role="assistant",
                content=(
                    "PRELIMINARY-DRAFT: inspect DATA EVIDENCE and choose a tool before answering."
                ),
            ),
            Message(
                role="assistant",
                content="FINALIZER-CONTENT-MUST-NOT-LEAK",
                tool_calls=[_i3a_final_answer_call("こんにちは (konnichiwa) means hello.")],
            ),
        ],
        trusted_origin="",
    )
    planner = Planner(
        provider,
        pep,
        max_retries=1,
        system_prompt="SAFETY-SENTINEL",
        persona_tone="strict",
        custom_persona_text="CUSTOM-PERSONA-SENTINEL",
        capabilities=ProviderCapabilities(supports_tool_calls=True),
    )
    runtime_tools = [
        {
            "type": "function",
            "function": {
                "name": "echo",
                "description": "Echo text",
                "parameters": {
                    "type": "object",
                    "properties": {"text": {"type": "string"}},
                    "required": ["text"],
                },
            },
        }
    ]

    result = await planner.propose_with_pep(
        "How do you say hello in Japanese?",
        PolicyContext(capabilities={Capability.FILE_READ}),
        pep=pep,
        tools=runtime_tools,
        finalize_response=True,
    )

    assert provider.calls == 2
    assert result.output.assistant_response == "こんにちは (konnichiwa) means hello."
    assert result.output.actions == []
    assert result.evaluated == []
    assert pep.calls == []
    assert "PRELIMINARY-DRAFT" not in result.output.assistant_response
    assert "FINALIZER-CONTENT" not in result.output.assistant_response
    assert provider.tools[0] == runtime_tools
    finalizer_tools = provider.tools[1]
    assert finalizer_tools is not None and len(finalizer_tools) == 1
    assert finalizer_tools[0]["function"]["name"] == "respond_to_user"
    assert set(finalizer_tools[0]["function"]["parameters"]["properties"]) == {"final_answer"}
    assert finalizer_tools[0]["function"]["parameters"]["additionalProperties"] is False
    assert (
        "Do not include tool or response-process commentary"
        in finalizer_tools[0]["function"]["parameters"]["properties"]["final_answer"]["description"]
    )
    finalizer_payload = "\n".join(message.content for message in provider.messages[1])
    assert "How do you say hello in Japanese?" in finalizer_payload
    assert "PRELIMINARY-DRAFT" in finalizer_payload
    assert "SAFETY-SENTINEL" in provider.messages[1][0].content
    assert "PERSONA STYLE INSTRUCTIONS (tone=strict)" in provider.messages[1][0].content
    assert "CUSTOM-PERSONA-SENTINEL" in provider.messages[1][0].content
    assert (
        "Do not mention whether tools are available, used, needed, or unnecessary"
        in provider.messages[1][0].content
    )
    assert result.provider_response is not None
    assert result.provider_response.message.content == "FINALIZER-CONTENT-MUST-NOT-LEAK"
    assert result.finalization_messages_sent == tuple(provider.messages[1])


@pytest.mark.asyncio
async def test_i3b_finalizer_includes_evidence_prior_grounding_contract() -> None:
    registry = _make_registry()
    pep = PEP(PolicyBundle(default_require_confirmation=False), registry)
    provider = StaticProvider(
        [
            Message(
                role="assistant",
                content="PRELIMINARY-PRIOR: add an unsupported category.",
            ),
            Message(
                role="assistant",
                content="FINALIZER-CONTENT-MUST-NOT-LEAK",
                tool_calls=[
                    _i3a_final_answer_call(
                        "The supplied note marks the second option as the recommendation."
                    )
                ],
            ),
        ],
        trusted_origin="",
    )
    planner = Planner(
        provider,
        pep,
        max_retries=1,
        system_prompt="SAFETY-SENTINEL",
        capabilities=ProviderCapabilities(supports_tool_calls=True),
    )
    rendered_context = (
        "=== TRUSTED SAME-SESSION USER CONTEXT (TRUSTED) ===\n"
        "- user: Red Lantern is marked as the recommendation.\n"
        "=== END TRUSTED SAME-SESSION USER CONTEXT ===\n\n"
        "=== USER REQUEST ===\n"
        "Which option did I recommend?\n\n"
        "=== END PAYLOAD ==="
    )

    result = await planner.propose_with_pep(
        rendered_context,
        PolicyContext(capabilities={Capability.FILE_READ}),
        pep=pep,
        tools=[],
        finalize_response=True,
    )

    assert result.output.assistant_response.startswith("The supplied note")
    assert provider.calls == 2
    finalizer_system = provider.messages[1][0].content
    assert "EVIDENCE AND PRIOR KNOWLEDGE GROUNDING" in finalizer_system
    assert "general/background knowledge" in finalizer_system
    assert "not implicit requests to persist" in finalizer_system
    assert "current USER REQUEST asks for that action" in finalizer_system
    assert "Do not call any runtime tool solely because" in finalizer_system
    assert "answer directly from model prior without a tool" in finalizer_system
    assert "Red Lantern is marked as the recommendation" in provider.messages[1][1].content
    assert "PRELIMINARY-PRIOR" in provider.messages[1][1].content
    finalizer_tools = provider.tools[1]
    assert finalizer_tools is not None
    assert set(finalizer_tools[0]["function"]["parameters"]["properties"]) == {"final_answer"}
    assert (
        "general/background knowledge"
        in finalizer_tools[0]["function"]["parameters"]["properties"]["final_answer"]["description"]
    )


@pytest.mark.asyncio
async def test_i3a_finalizer_retries_invalid_envelopes_without_leaking_draft() -> None:
    registry = _make_registry()
    pep = PEP(PolicyBundle(default_require_confirmation=False), registry)
    provider = StaticProvider(
        [
            Message(role="assistant", content="DRAFT-SENTINEL"),
            Message(
                role="assistant",
                content="invalid multiple-call envelope",
                tool_calls=[
                    _i3a_final_answer_call("first", call_id="invalid-1"),
                    _i3a_final_answer_call("second", call_id="invalid-2"),
                ],
            ),
            Message(
                role="assistant",
                content="invalid extra-field envelope",
                tool_calls=[
                    {
                        "id": "invalid-3",
                        "type": "function",
                        "function": {
                            "name": "respond_to_user",
                            "arguments": json.dumps(
                                {"final_answer": "answer", "extra": "not allowed"}
                            ),
                        },
                    }
                ],
            ),
            Message(
                role="assistant",
                content="ignored finalizer prose",
                tool_calls=[_i3a_final_answer_call("A typed, direct answer.", call_id="final-2")],
            ),
        ],
        trusted_origin="",
    )
    planner = Planner(provider, pep, max_retries=2)

    result = await planner.propose_with_pep(
        "answer directly",
        PolicyContext(capabilities={Capability.FILE_READ}),
        pep=pep,
        finalize_response=True,
    )

    assert provider.calls == 4
    assert result.output.assistant_response == "A typed, direct answer."
    assert "DRAFT-SENTINEL" not in result.output.assistant_response
    assert any(
        "invalid multiple-call envelope" in message.content
        for message in result.finalization_messages_sent
    )

    exhausted_provider = StaticProvider(
        [
            Message(role="assistant", content="EXHAUSTED-DRAFT"),
            Message(
                role="assistant",
                content="wrong response function",
                tool_calls=[
                    {
                        "id": "wrong-name",
                        "type": "function",
                        "function": {
                            "name": "echo",
                            "arguments": json.dumps({"final_answer": "not accepted"}),
                        },
                    }
                ],
            ),
        ],
        trusted_origin="",
    )
    exhausted_planner = Planner(exhausted_provider, pep, max_retries=1)

    with pytest.raises(PlannerOutputError, match="typed final answer") as exhausted:
        await exhausted_planner.propose_with_pep(
            "answer directly",
            PolicyContext(capabilities={Capability.FILE_READ}),
            pep=pep,
            finalize_response=True,
        )

    assert exhausted_provider.calls == 3
    assert exhausted.value.messages_sent
    assert exhausted.value.finalization_messages_sent
    assert any(
        "EXHAUSTED-DRAFT" in message.content
        for message in exhausted.value.finalization_messages_sent
    )


@pytest.mark.parametrize(
    ("tool_call", "error"),
    [
        (
            {
                "id": "wrong-type",
                "type": "metadata",
                "function": {
                    "name": "respond_to_user",
                    "arguments": json.dumps({"final_answer": "answer"}),
                },
            },
            "function tool call",
        ),
        (
            {
                "id": "wrong-name",
                "type": "function",
                "function": {
                    "name": "echo",
                    "arguments": json.dumps({"final_answer": "answer"}),
                },
            },
            "invalid function name",
        ),
        (
            {
                "id": "bad-json",
                "type": "function",
                "function": {
                    "name": "respond_to_user",
                    "arguments": "{not-json}",
                },
            },
            "not valid JSON",
        ),
        (
            {
                "id": "empty-answer",
                "type": "function",
                "function": {
                    "name": "respond_to_user",
                    "arguments": {"final_answer": "   "},
                },
            },
            "non-empty string",
        ),
    ],
)
def test_i3a_typed_final_answer_parser_rejects_non_contract_envelopes(
    tool_call: dict[str, Any],
    error: str,
) -> None:
    with pytest.raises(PlannerOutputError, match=error):
        Planner._parse_typed_final_answer(
            Message(role="assistant", content="ignored", tool_calls=[tool_call])
        )


@pytest.mark.asyncio
async def test_i3a_finalization_schema_is_fresh_per_request() -> None:
    registry = _make_registry()
    pep = PEP(PolicyBundle(default_require_confirmation=False), registry)
    provider = StaticProvider(
        [
            Message(role="assistant", content="first draft"),
            Message(
                role="assistant",
                tool_calls=[_i3a_final_answer_call("first answer", call_id="first")],
            ),
            Message(role="assistant", content="second draft"),
            Message(
                role="assistant",
                tool_calls=[_i3a_final_answer_call("second answer", call_id="second")],
            ),
        ],
        trusted_origin="",
    )
    planner = Planner(provider, pep, max_retries=0)

    first = await planner.propose_with_pep(
        "first request",
        PolicyContext(capabilities={Capability.FILE_READ}),
        pep=pep,
        finalize_response=True,
    )
    assert first.output.assistant_response == "first answer"
    first_tools = provider.tools[1]
    assert first_tools is not None
    first_tools[0]["function"]["name"] = "provider-mutated-name"

    second = await planner.propose_with_pep(
        "second request",
        PolicyContext(capabilities={Capability.FILE_READ}),
        pep=pep,
        finalize_response=True,
    )

    assert second.output.assistant_response == "second answer"
    second_tools = provider.tools[3]
    assert second_tools is not None
    assert second_tools[0]["function"]["name"] == "respond_to_user"


@pytest.mark.asyncio
async def test_i3a_action_and_local_fallback_paths_do_not_finalize() -> None:
    registry = _make_registry()
    pep = PEP(PolicyBundle(default_require_confirmation=False), registry)
    remote_action_provider = StaticProvider(
        [
            Message(
                role="assistant",
                content="Running echo.",
                tool_calls=[
                    {
                        "id": "echo-1",
                        "type": "function",
                        "function": {
                            "name": "echo",
                            "arguments": json.dumps({"text": "hello"}),
                        },
                    }
                ],
            )
        ],
        trusted_origin="",
    )
    action_planner = Planner(remote_action_provider, pep, max_retries=1)
    runtime_tools = [
        {
            "type": "function",
            "function": {
                "name": "echo",
                "parameters": {"type": "object"},
            },
        }
    ]

    action_result = await action_planner.propose(
        "echo hello",
        PolicyContext(capabilities={Capability.FILE_READ}),
        tools=runtime_tools,
    )

    assert remote_action_provider.calls == 1
    assert len(action_result.output.actions) == 1
    assert action_result.finalization_messages_sent == ()

    local_provider = StaticProvider(
        [Message(role="assistant", content="Local answer.")],
        trusted_origin="local-fallback",
    )
    local_planner = Planner(local_provider, pep, max_retries=1)
    local_result = await local_planner.propose(
        "answer locally",
        PolicyContext(capabilities={Capability.FILE_READ}),
    )

    assert local_provider.calls == 1
    assert local_result.output.assistant_response == "Local answer."
    assert local_result.finalization_messages_sent == ()

    content_only_provider = StaticProvider(
        [Message(role="assistant", content="Content-only route answer.")],
        trusted_origin="",
    )
    content_only_planner = Planner(
        content_only_provider,
        pep,
        max_retries=1,
        capabilities=ProviderCapabilities(
            supports_tool_calls=False,
            supports_content_tool_calls=True,
        ),
        tool_registry=registry,
    )
    content_only_result = await content_only_planner.propose(
        "answer without native tool calls",
        PolicyContext(capabilities={Capability.FILE_READ}),
    )

    assert content_only_provider.calls == 1
    assert content_only_result.output.assistant_response == "Content-only route answer."
    assert content_only_result.finalization_messages_sent == ()


@pytest.mark.asyncio
async def test_i3a_finalization_capacity_failure_is_terminal() -> None:
    from shisad.core.providers.base import ProviderContextCapacityError

    registry = _make_registry()
    pep = PEP(PolicyBundle(default_require_confirmation=False), registry)
    provider = StaticProvider(
        [Message(role="assistant", content="opaque preliminary draft " * 300)],
        trusted_origin="",
    )
    planner = Planner(
        provider,
        pep,
        max_retries=2,
        system_prompt="short safety rule",
        capabilities=ProviderCapabilities(
            supports_tool_calls=True,
            context_window_tokens=1024,
            output_reserve_tokens=128,
        ),
    )

    with pytest.raises(ProviderContextCapacityError) as caught:
        await planner.propose_with_pep(
            "hello",
            PolicyContext(capabilities={Capability.FILE_READ}),
            pep=pep,
            finalize_response=True,
        )

    assert provider.calls == 1
    assert caught.value.source == "planner_finalization_preflight"
    assert caught.value.messages_sent
    assert caught.value.finalization_messages_sent
    assert any(
        "opaque preliminary draft" in message.content
        for message in caught.value.finalization_messages_sent
    )


@pytest.mark.asyncio
async def test_i3a_general_planner_api_requires_explicit_response_finalization() -> None:
    registry = _make_registry()
    pep = PEP(PolicyBundle(default_require_confirmation=False), registry)
    provider = StaticProvider(
        [Message(role="assistant", content="Existing library response.")],
        trusted_origin="",
    )
    planner = Planner(provider, pep, max_retries=0)

    result = await planner.propose(
        "library caller",
        PolicyContext(capabilities={Capability.FILE_READ}),
    )

    assert provider.calls == 1
    assert result.output.assistant_response == "Existing library response."
    assert result.finalization_messages_sent == ()


def _make_registry() -> ToolRegistry:
    registry = ToolRegistry()
    registry.register(
        ToolDefinition(
            name=ToolName("echo"),
            description="Echo tool",
            parameters=[ToolParameter(name="text", type="string", required=True)],
            capabilities_required=[Capability.FILE_READ],
        )
    )
    return registry


@pytest.mark.asyncio
async def test_m1_t1_planner_accepts_plain_conversation_without_json_contract() -> None:
    registry = _make_registry()
    pep = PEP(PolicyBundle(default_require_confirmation=False), registry)
    planner = Planner(
        StaticProvider([Message(role="assistant", content="Hello from native planner")]),
        pep,
        max_retries=0,
    )

    result = await planner.propose(
        "hello",
        PolicyContext(capabilities={Capability.FILE_READ}),
    )

    assert result.output.assistant_response == "Hello from native planner"
    assert result.output.actions == []


@pytest.mark.asyncio
async def test_m1_t2_planner_extracts_native_tool_calls() -> None:
    registry = _make_registry()
    pep = PEP(PolicyBundle(default_require_confirmation=False), registry)
    planner = Planner(
        StaticProvider(
            [
                Message(
                    role="assistant",
                    content="Running echo.",
                    tool_calls=[
                        {
                            "id": "call_1",
                            "type": "function",
                            "function": {
                                "name": "echo",
                                "arguments": json.dumps({"text": "hello"}),
                            },
                        }
                    ],
                )
            ]
        ),
        pep,
        max_retries=0,
    )

    result = await planner.propose(
        "echo hello",
        PolicyContext(capabilities={Capability.FILE_READ}),
    )

    assert result.output.assistant_response == "Running echo."
    assert len(result.output.actions) == 1
    assert result.output.actions[0].action_id == "call_1"
    assert result.output.actions[0].tool_name == ToolName("echo")
    assert result.output.actions[0].arguments == {"text": "hello"}


@pytest.mark.asyncio
async def test_m1_t2_planner_drops_malformed_native_tool_calls() -> None:
    registry = _make_registry()
    pep = PEP(PolicyBundle(default_require_confirmation=False), registry)
    planner = Planner(
        StaticProvider(
            [
                Message(
                    role="assistant",
                    content="No valid calls.",
                    tool_calls=[
                        {"id": "x", "type": "function", "function": {"arguments": "{}"}},
                        {"id": "y", "type": "other"},
                    ],
                )
            ]
        ),
        pep,
        max_retries=0,
    )

    result = await planner.propose(
        "hello",
        PolicyContext(capabilities={Capability.FILE_READ}),
    )

    assert result.output.actions == []


@pytest.mark.asyncio
async def test_m5_cf_v0351_schema_strict_mode_rejects_malformed_native_tool_calls() -> None:
    registry = _make_registry()
    pep = PEP(PolicyBundle(default_require_confirmation=False), registry)
    planner = Planner(
        StaticProvider(
            [
                Message(
                    role="assistant",
                    content="No valid calls.",
                    tool_calls=[
                        {"id": "x", "type": "function", "function": {"arguments": "{}"}},
                        {"id": "y", "type": "other"},
                    ],
                )
            ]
        ),
        pep,
        max_retries=0,
        schema_strict_mode=True,
    )

    with pytest.raises(PlannerOutputError, match="strict schema validation"):
        await planner.propose(
            "hello",
            PolicyContext(capabilities={Capability.FILE_READ}),
        )


@pytest.mark.asyncio
async def test_gh55_schema_strict_mode_rejects_native_shell_exec_missing_command_intent() -> None:
    registry = _make_registry()
    registry.register(ShellExecTool.tool_definition())
    pep = PEP(PolicyBundle(default_require_confirmation=False), registry)
    planner = Planner(
        StaticProvider(
            [
                Message(
                    role="assistant",
                    content="Running status.",
                    tool_calls=[
                        {
                            "id": "call_shell",
                            "type": "function",
                            "function": {
                                "name": "shell.exec",
                                "arguments": json.dumps({"command": ["shisad", "status"]}),
                            },
                        }
                    ],
                )
            ]
        ),
        pep,
        max_retries=0,
        tool_registry=registry,
        schema_strict_mode=True,
    )

    with pytest.raises(PlannerOutputError, match="strict schema validation"):
        await planner.propose(
            "run shisad status",
            PolicyContext(capabilities={Capability.SHELL_EXEC}),
        )


@pytest.mark.asyncio
async def test_m1_t2_planner_drops_tool_call_with_invalid_json_arguments() -> None:
    registry = _make_registry()
    pep = PEP(PolicyBundle(default_require_confirmation=False), registry)
    planner = Planner(
        StaticProvider(
            [
                Message(
                    role="assistant",
                    content="Attempting echo",
                    tool_calls=[
                        {
                            "id": "call_bad_args",
                            "type": "function",
                            "function": {
                                "name": "echo",
                                "arguments": "{not-json}",
                            },
                        }
                    ],
                )
            ]
        ),
        pep,
        max_retries=0,
    )

    result = await planner.propose(
        "echo hi",
        PolicyContext(capabilities={Capability.FILE_READ}),
    )

    assert result.output.actions == []


@pytest.mark.asyncio
async def test_m1_t2_planner_drops_non_function_tool_call_envelope() -> None:
    registry = _make_registry()
    pep = PEP(PolicyBundle(default_require_confirmation=False), registry)
    planner = Planner(
        StaticProvider(
            [
                Message(
                    role="assistant",
                    content="No executable calls.",
                    tool_calls=[
                        {
                            "id": "meta_1",
                            "type": "metadata",
                            "function": {
                                "name": "echo",
                                "arguments": json.dumps({"text": "hello"}),
                            },
                        }
                    ],
                )
            ]
        ),
        pep,
        max_retries=0,
    )

    result = await planner.propose(
        "echo hi",
        PolicyContext(capabilities={Capability.FILE_READ}),
    )

    assert result.output.actions == []


@pytest.mark.asyncio
async def test_m1_t3_tool_proposals_always_go_through_pep() -> None:
    registry = _make_registry()
    base_pep = PEP(PolicyBundle(default_require_confirmation=False), registry)
    pep = RecordingPEP(base_pep)
    planner = Planner(
        StaticProvider(
            [
                Message(
                    role="assistant",
                    content="ok",
                    tool_calls=[
                        {
                            "id": "a1",
                            "type": "function",
                            "function": {
                                "name": "echo",
                                "arguments": json.dumps({"text": "hello"}),
                            },
                        }
                    ],
                )
            ]
        ),
        pep,
        max_retries=0,
    )

    result = await planner.propose(
        "run",
        PolicyContext(capabilities={Capability.FILE_READ}),
    )

    assert result.output.assistant_response == "ok"
    assert len(pep.calls) == 1
    assert pep.calls[0][0] == ToolName("echo")


@pytest.mark.asyncio
async def test_planner_trusted_context_rewrites_planner_mechanics_response() -> None:
    registry = _make_registry()
    pep = PEP(PolicyBundle(default_require_confirmation=False), registry)
    provider = StaticProvider(
        [
            Message(
                role="assistant",
                content=(
                    "I am a planning component and cannot directly call tools. "
                    "Please provide structured JSON."
                ),
            ),
            Message(
                role="assistant",
                content="Available tools include echo for simple text responses.",
            ),
        ]
    )
    planner = Planner(provider, pep, max_retries=1)

    result = await planner.propose(
        "what tools are available?",
        PolicyContext(capabilities={Capability.FILE_READ}),
    )

    assert provider.calls == 2
    lowered = result.output.assistant_response.lower()
    assert "planning component" not in lowered
    assert "structured json" not in lowered
    assert "available tools" in lowered


@pytest.mark.asyncio
async def test_planner_tainted_context_does_not_retry_mechanics_response() -> None:
    registry = _make_registry()
    pep = PEP(PolicyBundle(default_require_confirmation=False), registry)
    provider = StaticProvider(
        [
            Message(
                role="assistant",
                content=(
                    "I am a planning component and cannot directly call tools. "
                    "Please provide structured JSON."
                ),
            )
        ]
    )
    planner = Planner(provider, pep, max_retries=1)

    result = await planner.propose(
        "what tools are available?",
        PolicyContext(
            capabilities={Capability.FILE_READ},
            taint_labels={TaintLabel.UNTRUSTED},
        ),
    )

    assert provider.calls == 1
    assert "planning component" in result.output.assistant_response.lower()


@pytest.mark.asyncio
async def test_planner_passes_tool_payload_to_provider() -> None:
    registry = _make_registry()
    pep = PEP(PolicyBundle(default_require_confirmation=False), registry)
    provider = StaticProvider([Message(role="assistant", content="ok")])
    planner = Planner(provider, pep, max_retries=0)
    tools_payload = [
        {
            "type": "function",
            "function": {
                "name": "echo",
                "description": "Echo tool",
                "parameters": {"type": "object", "properties": {}, "required": []},
            },
        }
    ]

    result = await planner.propose(
        "hello",
        PolicyContext(capabilities={Capability.FILE_READ}),
        tools=tools_payload,
    )

    assert result.output.assistant_response == "ok"
    assert provider.tools == [tools_payload]


@pytest.mark.asyncio
async def test_planner_does_not_parse_legacy_json_content_as_actions() -> None:
    registry = _make_registry()
    pep = PEP(PolicyBundle(default_require_confirmation=False), registry)
    payload = json.dumps(
        {
            "assistant_response": "Running echo.",
            "actions": [
                {
                    "action_id": "a1",
                    "tool_name": "echo",
                    "arguments": {"text": "hello"},
                    "reasoning": "Need tool output",
                }
            ],
        }
    )
    planner = Planner(
        StaticProvider([Message(role="assistant", content=payload)]),
        pep,
        max_retries=0,
    )

    result = await planner.propose(
        "echo hello",
        PolicyContext(capabilities={Capability.FILE_READ}),
    )

    assert result.output.actions == []
    assert result.output.assistant_response == payload


@pytest.mark.asyncio
async def test_m5_rr2_schema_strict_mode_allows_non_tool_json_array_assistant_text() -> None:
    registry = _make_registry()
    pep = PEP(PolicyBundle(default_require_confirmation=False), registry)
    planner = Planner(
        StaticProvider([Message(role="assistant", content="[1, 2, 3]")]),
        pep,
        max_retries=0,
        schema_strict_mode=True,
    )

    result = await planner.propose(
        "show list",
        PolicyContext(capabilities={Capability.FILE_READ}),
    )

    assert result.output.actions == []
    assert result.output.assistant_response == "[1, 2, 3]"


@pytest.mark.asyncio
async def test_f15_planner_call_uses_explicit_current_policy_pep() -> None:
    registry = _make_registry()
    startup_pep = PEP(
        PolicyBundle(default_require_confirmation=False),
        registry,
    )
    current_pep = startup_pep.for_policy(
        PolicyBundle(
            default_require_confirmation=False,
            session_tool_allowlist=[ToolName("shell.exec")],
        )
    )
    planner = Planner(
        StaticProvider(
            [
                Message(
                    role="assistant",
                    content="Running echo.",
                    tool_calls=[
                        {
                            "id": "call-live-policy",
                            "type": "function",
                            "function": {
                                "name": "echo",
                                "arguments": json.dumps({"text": "hello"}),
                            },
                        }
                    ],
                )
            ]
        ),
        startup_pep,
        max_retries=0,
    )

    result = await planner.propose_with_pep(
        "echo hello",
        PolicyContext(capabilities={Capability.FILE_READ}),
        pep=current_pep,
    )

    assert len(result.evaluated) == 1
    assert result.evaluated[0].decision.kind == PEPDecisionKind.REJECT
    assert result.evaluated[0].decision.reason_code == "pep:tool_not_permitted"


@pytest.mark.asyncio
async def test_f15_validation_tool_does_not_leak_into_provider_manifest() -> None:
    registry = _make_registry()
    pep = PEP(PolicyBundle(default_require_confirmation=False), registry)
    provider = StaticProvider(
        [
            Message(
                role="assistant",
                content="Running echo.",
                tool_calls=[
                    {
                        "id": "call-runtime-gated",
                        "type": "function",
                        "function": {
                            "name": "echo",
                            "arguments": json.dumps({"text": "hello"}),
                        },
                    }
                ],
            )
        ]
    )
    planner = Planner(
        provider,
        pep,
        max_retries=0,
        tool_registry=registry,
        schema_strict_mode=True,
    )

    result = await planner.propose_with_pep(
        "echo hello",
        PolicyContext(capabilities={Capability.FILE_READ}),
        pep=pep,
        tools=[],
        validation_tool_names={"echo"},
    )

    assert provider.tools == [[]]
    assert [str(item.proposal.tool_name) for item in result.evaluated] == ["echo"]


@pytest.mark.asyncio
async def test_f15_content_validation_tool_does_not_leak_into_provider_manifest() -> None:
    registry = _make_registry()
    pep = PEP(PolicyBundle(default_require_confirmation=False), registry)
    provider = StaticProvider(
        [
            Message(
                role="assistant",
                content=json.dumps([{"name": "echo", "arguments": {"text": "hello"}}]),
            )
        ]
    )
    planner = Planner(
        provider,
        pep,
        max_retries=0,
        capabilities=ProviderCapabilities(
            supports_tool_calls=False,
            supports_content_tool_calls=True,
        ),
        tool_registry=registry,
        schema_strict_mode=True,
    )

    result = await planner.propose_with_pep(
        "echo hello",
        PolicyContext(capabilities={Capability.FILE_READ}),
        pep=pep,
        tools=[],
        validation_tool_names={"echo"},
    )

    assert provider.tools == [[]]
    assert [str(item.proposal.tool_name) for item in result.evaluated] == ["echo"]


@pytest.mark.asyncio
async def test_f15_concurrent_planner_policy_views_do_not_cross_contaminate() -> None:
    class ConcurrentProvider(StaticProvider):
        def __init__(self, response: Message) -> None:
            super().__init__([response])
            self._entered = 0
            self._both_entered = asyncio.Event()

        async def complete(
            self,
            messages: list[Message],
            tools: list[dict[str, Any]] | None = None,
        ) -> ProviderResponse:
            self._entered += 1
            if self._entered == 2:
                self._both_entered.set()
            await self._both_entered.wait()
            return await super().complete(messages, tools)

    registry = _make_registry()
    startup_pep = PEP(PolicyBundle(default_require_confirmation=False), registry)
    deny_pep = startup_pep.for_policy(
        PolicyBundle(
            default_require_confirmation=False,
            session_tool_allowlist=[ToolName("shell.exec")],
        )
    )
    response = Message(
        role="assistant",
        content="Running echo.",
        tool_calls=[
            {
                "id": "call-concurrent-policy",
                "type": "function",
                "function": {
                    "name": "echo",
                    "arguments": json.dumps({"text": "hello"}),
                },
            }
        ],
    )
    planner = Planner(ConcurrentProvider(response), startup_pep, max_retries=0)

    allowed, denied = await asyncio.gather(
        planner.propose_with_pep(
            "echo allowed",
            PolicyContext(capabilities={Capability.FILE_READ}),
            pep=startup_pep,
        ),
        planner.propose_with_pep(
            "echo denied",
            PolicyContext(capabilities={Capability.FILE_READ}),
            pep=deny_pep,
        ),
    )

    assert allowed.evaluated[0].decision.kind == PEPDecisionKind.ALLOW
    assert denied.evaluated[0].decision.kind == PEPDecisionKind.REJECT


@pytest.mark.asyncio
async def test_o0_validation_tool_names_are_concurrency_local_and_reset() -> None:
    class ValidationNamesProvider:
        def __init__(self) -> None:
            self.planner: Planner | None = None
            self._entered = 0
            self._both_entered = asyncio.Event()
            self.observed: dict[str, frozenset[str]] = {}

        async def complete(
            self,
            messages: list[Message],
            tools: list[dict[str, Any]] | None = None,
        ) -> ProviderResponse:
            _ = tools
            assert self.planner is not None
            user_content = messages[-1].content
            self.observed[user_content] = self.planner._validation_tool_names.get()
            if user_content != "after reset":
                self._entered += 1
                if self._entered == 2:
                    self._both_entered.set()
                await self._both_entered.wait()
            return ProviderResponse(
                message=Message(role="assistant", content="No action needed."),
                finish_reason="stop",
                usage={},
            )

    registry = _make_registry()
    pep = PEP(PolicyBundle(default_require_confirmation=False), registry)
    provider = ValidationNamesProvider()
    planner = Planner(provider, pep, max_retries=0)
    provider.planner = planner
    context = PolicyContext(capabilities={Capability.FILE_READ})

    await asyncio.gather(
        planner.propose_with_pep(
            "resolve action",
            context,
            pep=pep,
            validation_tool_names={"action.resolve"},
        ),
        planner.propose_with_pep(
            "resume lockdown",
            context,
            pep=pep,
            validation_tool_names={"lockdown.resume"},
        ),
    )
    await planner.propose("after reset", context)

    assert provider.observed == {
        "resolve action": frozenset({"action.resolve"}),
        "resume lockdown": frozenset({"lockdown.resume"}),
        "after reset": frozenset(),
    }
