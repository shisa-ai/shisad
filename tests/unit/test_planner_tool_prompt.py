"""M2 planner tool prompt parity coverage for content-tool routes."""

from __future__ import annotations

from typing import Any

import pytest

from shisad.core.planner import Planner, PlannerOutput
from shisad.core.providers.base import Message, ProviderResponse
from shisad.core.providers.capabilities import ProviderCapabilities
from shisad.core.tools.names import canonical_tool_name
from shisad.core.tools.registry import ToolRegistry
from shisad.core.tools.schema import ToolDefinition, ToolParameter, tool_definitions_to_openai
from shisad.core.types import Capability, ToolName
from shisad.security.pep import PEP, PolicyContext
from shisad.security.policy import PolicyBundle


class _RecordingProvider:
    def __init__(self) -> None:
        self.messages: list[list[Message]] = []

    async def complete(
        self,
        messages: list[Message],
        tools: list[dict[str, Any]] | None = None,
    ) -> ProviderResponse:
        _ = tools
        self.messages.append(list(messages))
        return ProviderResponse(message=Message(role="assistant", content="ok"), usage={})


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
    registry.register(
        ToolDefinition(
            name=ToolName("web.search"),
            description="Search public web",
            parameters=[ToolParameter(name="query", type="string", required=True)],
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
async def test_m2_tool_prompt_fragment_is_injected_for_content_tool_routes() -> None:
    registry = _make_registry()
    provider = _RecordingProvider()
    pep = PEP(PolicyBundle(default_require_confirmation=False), registry)
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

    await planner.propose(
        "hello",
        PolicyContext(capabilities={Capability.FILE_READ}),
        tools=_tools_payload(registry, {"echo"}),
    )

    system_prompt = provider.messages[0][0].content
    assert "CONTENT TOOL-CALLING RUNTIME MANIFEST" in system_prompt
    assert "This route does not support native `tool_calls` fields." in system_prompt
    assert "<tool_call>{\"name\": \"...\", \"arguments\": {...}}</tool_call>" in system_prompt
    assert "echo" in system_prompt
    assert "Echo text" in system_prompt
    assert "web.search" not in system_prompt
    assert "do not narrate the intended tool call" in system_prompt.lower()
    assert "for note, todo, and reminder requests" in system_prompt.lower()


@pytest.mark.asyncio
async def test_m2_tool_prompt_fragment_is_not_injected_for_native_tool_routes() -> None:
    registry = _make_registry()
    provider = _RecordingProvider()
    pep = PEP(PolicyBundle(default_require_confirmation=False), registry)
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

    await planner.propose(
        "hello",
        PolicyContext(capabilities={Capability.FILE_READ}),
        tools=_tools_payload(registry, {"echo"}),
    )

    system_prompt = provider.messages[0][0].content
    assert "CONTENT TOOL-CALLING RUNTIME MANIFEST" not in system_prompt


@pytest.mark.asyncio
async def test_m2_tool_prompt_fragment_is_not_injected_when_content_fallback_disabled() -> None:
    registry = _make_registry()
    provider = _RecordingProvider()
    pep = PEP(PolicyBundle(default_require_confirmation=False), registry)
    planner = Planner(
        provider,
        pep,
        max_retries=0,
        capabilities=ProviderCapabilities(
            supports_tool_calls=False,
            supports_content_tool_calls=False,
        ),
        tool_registry=registry,
    )

    await planner.propose(
        "hello",
        PolicyContext(capabilities={Capability.FILE_READ}),
        tools=_tools_payload(registry, {"echo"}),
    )

    system_prompt = provider.messages[0][0].content
    assert "CONTENT TOOL-CALLING RUNTIME MANIFEST" not in system_prompt
    assert "TOOL CALLING IS DISABLED ON THIS ROUTE" in system_prompt


def test_m1_trusted_conversation_repair_flags_no_tool_call_meta_commentary() -> None:
    output = PlannerOutput(
        assistant_response=(
            "Hello there. No tool call is needed for this request because it is only "
            "a greeting."
        ),
        actions=[],
    )

    assert Planner._needs_trusted_conversation_repair(output) is True
