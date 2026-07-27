"""M1 RF-014: planner native tool-calling and safety behavior."""

from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest

from shisad.core.planner import Planner, PlannerOutputError
from shisad.core.providers.base import Message, ProviderResponse
from shisad.core.providers.capabilities import ProviderCapabilities
from shisad.core.tools.builtin.shell_exec import ShellExecTool
from shisad.core.tools.registry import ToolRegistry
from shisad.core.tools.schema import ToolDefinition, ToolParameter
from shisad.core.types import Capability, PEPDecision, PEPDecisionKind, TaintLabel, ToolName
from shisad.security.pep import PEP, PolicyContext
from shisad.security.policy import PolicyBundle


class StaticProvider:
    def __init__(self, responses: list[Message]) -> None:
        self._responses = responses
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
