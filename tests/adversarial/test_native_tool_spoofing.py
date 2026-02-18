"""RF-014 adversarial checks: native tool-calls cannot bypass PEP/registry truth."""

from __future__ import annotations

import json
from typing import Any

import pytest

from shisad.core.planner import Planner
from shisad.core.providers.base import Message, ProviderResponse
from shisad.core.tools.registry import ToolRegistry
from shisad.core.tools.schema import ToolDefinition, ToolParameter
from shisad.core.types import Capability, PEPDecisionKind, ToolName
from shisad.security.pep import PEP, PolicyContext
from shisad.security.policy import PolicyBundle


class StaticProvider:
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


@pytest.mark.asyncio
async def test_native_tool_call_for_unknown_tool_is_rejected_by_pep() -> None:
    registry = _make_registry()
    pep = PEP(PolicyBundle(default_require_confirmation=False), registry)
    planner = Planner(
        StaticProvider(
            Message(
                role="assistant",
                content="Attempting to run a tool.",
                tool_calls=[
                    {
                        "id": "call_1",
                        "type": "function",
                        "function": {
                            "name": "query_document",
                            "arguments": json.dumps({"query": "secret"}),
                        },
                    }
                ],
            )
        ),
        pep,
        max_retries=0,
    )

    result = await planner.propose(
        "find secret",
        PolicyContext(capabilities={Capability.FILE_READ}),
    )

    assert len(result.evaluated) == 1
    assert result.evaluated[0].proposal.tool_name == ToolName("query_document")
    assert result.evaluated[0].decision.kind == PEPDecisionKind.REJECT


@pytest.mark.asyncio
async def test_text_only_tool_spoof_does_not_create_actions() -> None:
    registry = _make_registry()
    pep = PEP(PolicyBundle(default_require_confirmation=False), registry)
    planner = Planner(
        StaticProvider(
            Message(
                role="assistant",
                content=(
                    "I can call query_document and execute_python for this request. "
                    "(No native tool calls were provided.)"
                ),
            )
        ),
        pep,
        max_retries=0,
    )

    result = await planner.propose(
        "summarize",
        PolicyContext(capabilities={Capability.FILE_READ}),
    )

    assert result.output.actions == []
    assert result.evaluated == []
