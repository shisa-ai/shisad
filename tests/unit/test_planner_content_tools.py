"""M2 planner content-based tool-call extraction coverage."""

from __future__ import annotations

import json
from typing import Any

import pytest

from shisad.core.planner import Planner
from shisad.core.providers.base import Message, ProviderResponse
from shisad.core.providers.capabilities import ProviderCapabilities
from shisad.core.tools.names import canonical_tool_name
from shisad.core.tools.registry import ToolRegistry
from shisad.core.tools.schema import ToolDefinition, ToolParameter, tool_definitions_to_openai
from shisad.core.types import Capability, ToolName
from shisad.security.pep import PEP, PolicyContext
from shisad.security.policy import PolicyBundle


class _StaticProvider:
    def __init__(self, responses: list[Message]) -> None:
        self._responses = responses
        self.calls = 0

    async def complete(
        self,
        messages: list[Message],
        tools: list[dict[str, Any]] | None = None,
    ) -> ProviderResponse:
        _ = (messages, tools)
        index = min(self.calls, len(self._responses) - 1)
        self.calls += 1
        return ProviderResponse(message=self._responses[index], finish_reason="stop", usage={})


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
    registry.register(
        ToolDefinition(
            name=ToolName("web.search"),
            description="Web search",
            parameters=[
                ToolParameter(name="query", type="string", required=True),
                ToolParameter(name="limit", type="integer", required=False),
            ],
            capabilities_required=[Capability.HTTP_REQUEST],
        )
    )
    return registry


def _tools_payload(registry: ToolRegistry, names: set[str]) -> list[dict[str, Any]]:
    payload = tool_definitions_to_openai(registry.list_tools())
    return [
        item
        for item in payload
        if canonical_tool_name(str(item.get("function", {}).get("name", ""))) in names
    ]


@pytest.mark.asyncio
async def test_m2_planner_extracts_hermes_content_tool_calls_when_capability_enabled() -> None:
    registry = _make_registry()
    pep = PEP(PolicyBundle(default_require_confirmation=False), registry)
    provider = _StaticProvider(
        [
            Message(
                role="assistant",
                content=(
                    "Running tool. "
                    '<tool_call>{"name":"echo","arguments":{"text":"hello"}}</tool_call>'
                ),
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
    )

    result = await planner.propose(
        "echo hello",
        PolicyContext(capabilities={Capability.FILE_READ}),
        tools=_tools_payload(registry, {"echo"}),
    )

    assert result.output.assistant_response == "Running tool."
    assert len(result.output.actions) == 1
    assert result.output.actions[0].tool_name == ToolName("echo")
    assert result.output.actions[0].arguments == {"text": "hello"}


@pytest.mark.asyncio
async def test_m2_planner_prefers_native_tool_calls_over_content_fallback() -> None:
    registry = _make_registry()
    pep = PEP(PolicyBundle(default_require_confirmation=False), registry)
    provider = _StaticProvider(
        [
            Message(
                role="assistant",
                content=(
                    "native wins "
                    '<tool_call>{"name":"web.search","arguments":{"query":"ignored"}}</tool_call>'
                ),
                tool_calls=[
                    {
                        "id": "native_1",
                        "type": "function",
                        "function": {
                            "name": "echo",
                            "arguments": json.dumps({"text": "native"}),
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
        capabilities=ProviderCapabilities(
            supports_tool_calls=False,
            supports_content_tool_calls=True,
        ),
        tool_registry=registry,
    )

    result = await planner.propose(
        "test",
        PolicyContext(capabilities={Capability.FILE_READ, Capability.HTTP_REQUEST}),
        tools=_tools_payload(registry, {"echo", "web.search"}),
    )

    assert len(result.output.actions) == 1
    assert result.output.actions[0].action_id == "native_1"
    assert result.output.actions[0].tool_name == ToolName("echo")
    assert result.output.actions[0].arguments == {"text": "native"}


@pytest.mark.asyncio
async def test_m2_planner_does_not_extract_content_tool_calls_when_native_supported() -> None:
    registry = _make_registry()
    pep = PEP(PolicyBundle(default_require_confirmation=False), registry)
    provider = _StaticProvider(
        [
            Message(
                role="assistant",
                content='<tool_call>{"name":"echo","arguments":{"text":"ignored"}}</tool_call>',
            )
        ]
    )
    planner = Planner(
        provider,
        pep,
        max_retries=0,
        capabilities=ProviderCapabilities(
            supports_tool_calls=True,
            supports_content_tool_calls=True,
        ),
        tool_registry=registry,
    )

    result = await planner.propose(
        "test",
        PolicyContext(capabilities={Capability.FILE_READ}),
        tools=_tools_payload(registry, {"echo"}),
    )

    assert result.output.actions == []
    assert "<tool_call>" in result.output.assistant_response


@pytest.mark.asyncio
async def test_m2_planner_extracts_json_array_tool_calls_from_content() -> None:
    registry = _make_registry()
    pep = PEP(PolicyBundle(default_require_confirmation=False), registry)
    provider = _StaticProvider(
        [
            Message(
                role="assistant",
                content='[{"name":"web.search","arguments":{"query":"shisad","limit":2}}]',
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
    )

    result = await planner.propose(
        "search shisad",
        PolicyContext(capabilities={Capability.HTTP_REQUEST}),
        tools=_tools_payload(registry, {"web.search"}),
    )

    assert result.output.assistant_response == ""
    assert len(result.output.actions) == 1
    assert result.output.actions[0].tool_name == ToolName("web.search")
    assert result.output.actions[0].arguments == {"query": "shisad", "limit": 2}


@pytest.mark.asyncio
async def test_m2_planner_preserves_json_list_text_with_extra_fields() -> None:
    registry = _make_registry()
    pep = PEP(PolicyBundle(default_require_confirmation=False), registry)
    content = '[{"name":"web.search","arguments":{"query":"shisad"},"note":"keep"}]'
    provider = _StaticProvider([Message(role="assistant", content=content)])
    planner = Planner(
        provider,
        pep,
        max_retries=0,
        capabilities=ProviderCapabilities(
            supports_tool_calls=False,
            supports_content_tool_calls=True,
        ),
        tool_registry=registry,
    )

    result = await planner.propose(
        "search shisad",
        PolicyContext(capabilities={Capability.HTTP_REQUEST}),
        tools=_tools_payload(registry, {"web.search"}),
    )

    assert result.output.assistant_response == content
    assert len(result.output.actions) == 1
    assert result.output.actions[0].tool_name == ToolName("web.search")
    assert result.output.actions[0].arguments == {"query": "shisad"}


@pytest.mark.asyncio
async def test_m2_planner_rejects_mixed_valid_and_malformed_content_tool_calls() -> None:
    registry = _make_registry()
    pep = PEP(PolicyBundle(default_require_confirmation=False), registry)
    provider = _StaticProvider(
        [
            Message(
                role="assistant",
                content=(
                    '<tool_call>{"name":"echo","arguments":{"text":"ok"}}</tool_call>'
                    " <tool_call>{not-json}</tool_call>"
                ),
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
    )

    result = await planner.propose(
        "echo",
        PolicyContext(capabilities={Capability.FILE_READ}),
        tools=_tools_payload(registry, {"echo"}),
    )

    assert result.output.actions == []


@pytest.mark.asyncio
async def test_m1_rlc4_planner_skips_unknown_content_tool_calls_but_keeps_valid_calls() -> None:
    registry = _make_registry()
    pep = PEP(PolicyBundle(default_require_confirmation=False), registry)
    provider = _StaticProvider(
        [
            Message(
                role="assistant",
                content=(
                    '<tool_call>{"name":"unknown.tool","arguments":{"x":1}}</tool_call>'
                    ' <tool_call>{"name":"echo","arguments":{"text":"ok"}}</tool_call>'
                ),
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
    )

    result = await planner.propose(
        "echo",
        PolicyContext(capabilities={Capability.FILE_READ}),
        tools=_tools_payload(registry, {"echo"}),
    )

    assert len(result.output.actions) == 1
    assert result.output.actions[0].tool_name == ToolName("echo")
    assert result.output.actions[0].arguments == {"text": "ok"}


@pytest.mark.asyncio
async def test_m2_planner_enforces_content_tool_call_count_bound() -> None:
    registry = _make_registry()
    pep = PEP(PolicyBundle(default_require_confirmation=False), registry)
    calls = [
        '<tool_call>{"name":"echo","arguments":{"text":"x"}}</tool_call>'
        for _ in range(11)
    ]
    provider = _StaticProvider([Message(role="assistant", content=" ".join(calls))])
    planner = Planner(
        provider,
        pep,
        max_retries=0,
        capabilities=ProviderCapabilities(
            supports_tool_calls=False,
            supports_content_tool_calls=True,
        ),
        tool_registry=registry,
    )

    result = await planner.propose(
        "echo",
        PolicyContext(capabilities={Capability.FILE_READ}),
        tools=_tools_payload(registry, {"echo"}),
    )

    assert result.output.actions == []


@pytest.mark.asyncio
async def test_m2_planner_enforces_json_array_tool_call_count_bound() -> None:
    registry = _make_registry()
    pep = PEP(PolicyBundle(default_require_confirmation=False), registry)
    payload = json.dumps(
        [{"name": "echo", "arguments": {"text": f"x-{idx}"}} for idx in range(11)]
    )
    provider = _StaticProvider([Message(role="assistant", content=payload)])
    planner = Planner(
        provider,
        pep,
        max_retries=0,
        capabilities=ProviderCapabilities(
            supports_tool_calls=False,
            supports_content_tool_calls=True,
        ),
        tool_registry=registry,
    )

    result = await planner.propose(
        "echo",
        PolicyContext(capabilities={Capability.FILE_READ}),
        tools=_tools_payload(registry, {"echo"}),
    )

    assert result.output.actions == []


@pytest.mark.asyncio
async def test_m2_planner_enforces_content_tool_argument_size_bound() -> None:
    registry = _make_registry()
    pep = PEP(PolicyBundle(default_require_confirmation=False), registry)
    oversized = "x" * 10_300
    provider = _StaticProvider(
        [
            Message(
                role="assistant",
                content=(
                    "<tool_call>"
                    f"{{\"name\":\"echo\",\"arguments\":{{\"text\":\"{oversized}\"}}}}"
                    "</tool_call>"
                ),
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
    )

    result = await planner.propose(
        "echo",
        PolicyContext(capabilities={Capability.FILE_READ}),
        tools=_tools_payload(registry, {"echo"}),
    )

    assert result.output.actions == []


@pytest.mark.asyncio
async def test_m2_planner_enforces_content_tool_total_payload_size_bound() -> None:
    registry = _make_registry()
    pep = PEP(PolicyBundle(default_require_confirmation=False), registry)
    oversized_content = (
        '<tool_call>{"name":"echo","arguments":{"text":"ok"}}</tool_call>'
        + ("x" * 120_000)
    )
    provider = _StaticProvider([Message(role="assistant", content=oversized_content)])
    planner = Planner(
        provider,
        pep,
        max_retries=0,
        capabilities=ProviderCapabilities(
            supports_tool_calls=False,
            supports_content_tool_calls=True,
        ),
        tool_registry=registry,
    )

    result = await planner.propose(
        "echo",
        PolicyContext(capabilities={Capability.FILE_READ}),
        tools=_tools_payload(registry, {"echo"}),
    )

    assert result.output.actions == []


@pytest.mark.asyncio
async def test_m2_planner_rejects_content_tool_call_not_in_runtime_tools_payload() -> None:
    registry = _make_registry()
    pep = PEP(PolicyBundle(default_require_confirmation=False), registry)
    provider = _StaticProvider(
        [
            Message(
                role="assistant",
                content='<tool_call>{"name":"shell.exec","arguments":{"command":["id"]}}</tool_call>',
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
    )

    result = await planner.propose(
        "run id",
        PolicyContext(capabilities={Capability.FILE_READ}),
        tools=_tools_payload(registry, {"echo"}),
    )

    assert result.output.actions == []


@pytest.mark.asyncio
async def test_m2_planner_content_tool_calls_are_disabled_when_tool_registry_missing() -> None:
    pep = PEP(PolicyBundle(default_require_confirmation=False), ToolRegistry())
    provider = _StaticProvider(
        [
            Message(
                role="assistant",
                content='<tool_call>{"name":"echo","arguments":{"text":"ignored"}}</tool_call>',
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
        tool_registry=None,
    )

    result = await planner.propose(
        "echo",
        PolicyContext(capabilities={Capability.FILE_READ}),
        tools=[
            {
                "type": "function",
                "function": {
                    "name": "echo",
                    "description": "Echo tool",
                    "parameters": {
                        "type": "object",
                        "properties": {"text": {"type": "string"}},
                        "required": ["text"],
                    },
                },
            }
        ],
    )

    assert result.output.actions == []
    assert "<tool_call>" in result.output.assistant_response
