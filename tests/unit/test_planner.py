"""M1 RF-014: planner native tool-calling and safety behavior."""

from __future__ import annotations

import json
from typing import Any

import pytest

from shisad.core.planner import Planner, PlannerOutputError
from shisad.core.providers.base import Message, ProviderResponse
from shisad.core.tools.registry import ToolRegistry
from shisad.core.tools.schema import ToolDefinition, ToolParameter
from shisad.core.types import Capability, PEPDecision, TaintLabel, ToolName
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
async def test_m1_t2_planner_defaults_invalid_tool_arguments_to_empty_object() -> None:
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

    assert len(result.output.actions) == 1
    assert result.output.actions[0].arguments == {}


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
async def test_planner_legacy_json_fallback_disabled_by_default() -> None:
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
async def test_planner_legacy_json_fallback_can_be_enabled() -> None:
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
        legacy_json_fallback=True,
    )

    result = await planner.propose(
        "echo hello",
        PolicyContext(capabilities={Capability.FILE_READ}),
    )

    assert result.output.assistant_response == "Running echo."
    assert len(result.output.actions) == 1
    assert result.output.actions[0].tool_name == ToolName("echo")


@pytest.mark.asyncio
async def test_planner_tainted_context_fails_closed_on_legacy_json_parse_error() -> None:
    registry = _make_registry()
    pep = PEP(PolicyBundle(default_require_confirmation=False), registry)
    provider = StaticProvider(
        [
            Message(role="assistant", content='{"assistant_response": "broken"'),
            Message(role="assistant", content='{"assistant_response": "would-have-passed"}'),
        ]
    )
    planner = Planner(
        provider,
        pep,
        max_retries=1,
        legacy_json_fallback=True,
    )

    with pytest.raises(PlannerOutputError):
        await planner.propose(
            "hello",
            PolicyContext(
                capabilities={Capability.FILE_READ},
                taint_labels={TaintLabel.UNTRUSTED},
            ),
        )
    assert provider.calls == 1
