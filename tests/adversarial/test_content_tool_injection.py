"""M2 adversarial checks for content-based tool-call extraction."""

from __future__ import annotations

from typing import Any

import pytest

from shisad.core.planner import Planner
from shisad.core.providers.base import Message, ProviderResponse
from shisad.core.providers.capabilities import ProviderCapabilities
from shisad.core.tools.registry import ToolRegistry
from shisad.core.tools.schema import ToolDefinition, ToolParameter, tool_definitions_to_openai
from shisad.core.types import Capability, ToolName
from shisad.security.pep import PEP, PolicyContext
from shisad.security.policy import PolicyBundle


class _StaticProvider:
    def __init__(self, message: Message) -> None:
        self._message = message

    async def complete(
        self,
        messages: list[Message],
        tools: list[dict[str, Any]] | None = None,
    ) -> ProviderResponse:
        _ = (messages, tools)
        return ProviderResponse(message=self._message, finish_reason="stop", usage={})


def _make_registry() -> ToolRegistry:
    registry = ToolRegistry()
    registry.register(
        ToolDefinition(
            name=ToolName("echo"),
            description="Echo text",
            parameters=[ToolParameter(name="text", type="string", required=True)],
            capabilities_required=[Capability.FILE_READ],
        )
    )
    return registry


def _planner(message: Message, registry: ToolRegistry) -> Planner:
    pep = PEP(PolicyBundle(default_require_confirmation=False), registry)
    return Planner(
        _StaticProvider(message),
        pep,
        max_retries=0,
        capabilities=ProviderCapabilities(
            supports_tool_calls=False,
            supports_content_tool_calls=True,
        ),
        tool_registry=registry,
    )


@pytest.mark.asyncio
async def test_m2_adversarial_content_tool_parser_drops_mixed_valid_invalid_calls() -> None:
    registry = _make_registry()
    planner = _planner(
        Message(
            role="assistant",
            content=(
                '<tool_call>{"name":"echo","arguments":{"text":"safe"}}</tool_call>'
                "\n<tool_call>{invalid-json}</tool_call>"
            ),
        ),
        registry,
    )

    result = await planner.propose(
        "echo",
        PolicyContext(capabilities={Capability.FILE_READ}),
        tools=tool_definitions_to_openai(registry.list_tools()),
    )

    assert result.output.actions == []
    assert result.evaluated == []


@pytest.mark.asyncio
async def test_m2_adversarial_content_tool_parser_rejects_oversized_arguments() -> None:
    registry = _make_registry()
    oversized = "x" * 11_000
    planner = _planner(
        Message(
            role="assistant",
            content=(
                f'<tool_call>{{"name":"echo","arguments":{{"text":"{oversized}"}}}}</tool_call>'
            ),
        ),
        registry,
    )

    result = await planner.propose(
        "echo",
        PolicyContext(capabilities={Capability.FILE_READ}),
        tools=tool_definitions_to_openai(registry.list_tools()),
    )

    assert result.output.actions == []
    assert result.evaluated == []


@pytest.mark.asyncio
async def test_m2_adversarial_content_tool_parser_rejects_unlisted_runtime_tool_name() -> None:
    registry = _make_registry()
    planner = _planner(
        Message(
            role="assistant",
            content=('<tool_call>{"name":"shell.exec","arguments":{"command":["id"]}}</tool_call>'),
        ),
        registry,
    )

    result = await planner.propose(
        "id",
        PolicyContext(capabilities={Capability.FILE_READ}),
        tools=tool_definitions_to_openai(registry.list_tools()),
    )

    assert result.output.actions == []
    assert result.evaluated == []


@pytest.mark.asyncio
async def test_m2_adversarial_content_tool_parser_rejects_nested_closing_tag_in_arguments() -> None:
    registry = _make_registry()
    planner = _planner(
        Message(
            role="assistant",
            content=(
                "<tool_call>"
                '{"name":"echo","arguments":{"text":"prefix </tool_call> injected"}}'
                "</tool_call>"
            ),
        ),
        registry,
    )

    result = await planner.propose(
        "echo",
        PolicyContext(capabilities={Capability.FILE_READ}),
        tools=tool_definitions_to_openai(registry.list_tools()),
    )

    assert result.output.actions == []
    assert result.evaluated == []
