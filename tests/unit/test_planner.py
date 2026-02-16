"""M1.T1-T3: planner strict output and PEP gating."""

from __future__ import annotations

import json
from typing import Any

import pytest

from shisad.core.planner import Planner, PlannerOutputError
from shisad.core.providers.base import Message, ProviderResponse
from shisad.core.tools.registry import ToolRegistry
from shisad.core.tools.schema import ToolDefinition, ToolParameter
from shisad.core.types import Capability, PEPDecision, ToolName
from shisad.security.pep import PEP, PolicyContext
from shisad.security.policy import PolicyBundle


class StaticProvider:
    def __init__(self, responses: list[str]) -> None:
        self._responses = responses
        self.calls = 0

    async def complete(
        self,
        messages: list[Message],
        tools: list[dict[str, Any]] | None = None,
    ) -> ProviderResponse:
        index = min(self.calls, len(self._responses) - 1)
        self.calls += 1
        return ProviderResponse(
            message=Message(role="assistant", content=self._responses[index]),
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
async def test_m1_t1_planner_rejects_non_json_output() -> None:
    registry = _make_registry()
    pep = PEP(PolicyBundle(default_require_confirmation=False), registry)
    planner = Planner(StaticProvider(["this is not json"]), pep, max_retries=0)

    with pytest.raises(PlannerOutputError):
        await planner.propose(
            "hello",
            PolicyContext(capabilities={Capability.FILE_READ}),
        )


@pytest.mark.asyncio
async def test_m1_t2_planner_rejects_schema_violating_json() -> None:
    registry = _make_registry()
    pep = PEP(PolicyBundle(default_require_confirmation=False), registry)
    invalid_payload = json.dumps(
        {
            "actions": [
                {
                    "action_id": "a1",
                    "tool_name": "echo",
                    # missing arguments/reasoning/data_sources
                }
            ]
        }
    )
    planner = Planner(StaticProvider([invalid_payload]), pep, max_retries=0)

    with pytest.raises(PlannerOutputError):
        await planner.propose(
            "hello",
            PolicyContext(capabilities={Capability.FILE_READ}),
        )


@pytest.mark.asyncio
async def test_m1_t2_planner_normalizes_noncanonical_report_anomaly_payload() -> None:
    registry = _make_registry()
    pep = PEP(PolicyBundle(default_require_confirmation=False), registry)
    noncanonical_payload = json.dumps(
        {
            "action": "report_anomaly",
            "reason": "Potential prompt injection in untrusted input.",
        }
    )
    planner = Planner(StaticProvider([noncanonical_payload]), pep, max_retries=0)

    result = await planner.propose(
        "hello",
        PolicyContext(capabilities={Capability.FILE_READ}),
    )
    assert result.output.assistant_response.startswith("Potential prompt injection")
    assert len(result.output.actions) == 1
    assert result.output.actions[0].tool_name == ToolName("report_anomaly")


@pytest.mark.asyncio
async def test_m1_t2_planner_normalizes_assistant_response_object_payload() -> None:
    registry = _make_registry()
    pep = PEP(PolicyBundle(default_require_confirmation=False), registry)
    payload = json.dumps(
        {
            "assistant_response": {"type": "error", "message": "Hello there"},
            "actions": [],
        }
    )
    planner = Planner(StaticProvider([payload]), pep, max_retries=0)

    result = await planner.propose(
        "hello",
        PolicyContext(capabilities={Capability.FILE_READ}),
    )
    assert result.output.assistant_response == "Hello there"
    assert result.output.actions == []


@pytest.mark.asyncio
async def test_m1_t3_tool_proposals_always_go_through_pep() -> None:
    registry = _make_registry()
    base_pep = PEP(PolicyBundle(default_require_confirmation=False), registry)
    pep = RecordingPEP(base_pep)

    payload = json.dumps(
        {
            "assistant_response": "ok",
            "actions": [
                {
                    "action_id": "a1",
                    "tool_name": "echo",
                    "arguments": {"text": "hello"},
                    "reasoning": "Need tool output",
                    "data_sources": ["msg:1"],
                }
            ],
        }
    )
    planner = Planner(StaticProvider([payload]), pep, max_retries=0)

    result = await planner.propose(
        "run",
        PolicyContext(capabilities={Capability.FILE_READ}),
    )

    assert result.output.assistant_response == "ok"
    assert len(pep.calls) == 1
    assert pep.calls[0][0] == ToolName("echo")
