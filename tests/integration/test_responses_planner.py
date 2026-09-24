"""Responses calls become ordinary planner proposals subject to the existing PEP."""

import pytest

from shisad.core.config import ModelConfig
from shisad.core.planner import Planner
from shisad.core.providers.base import OpenAICompatibleProvider
from shisad.core.providers.routed_openai import RoutedOpenAIProvider
from shisad.core.providers.routing import ModelRouter
from shisad.core.tools.registry import ToolRegistry
from shisad.core.tools.schema import ToolDefinition, ToolParameter
from shisad.core.types import Capability, PEPDecisionKind, ToolName
from shisad.security.pep import PEP, PolicyContext
from shisad.security.policy import PolicyBundle


@pytest.mark.asyncio
@pytest.mark.parametrize("authorized", [True, False])
async def test_responses_function_calls_keep_normal_policy_enforcement(monkeypatch, authorized):
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    registry = ToolRegistry()
    registry.register(
        ToolDefinition(
            name=ToolName("fs.read"),
            description="Read a file",
            parameters=[ToolParameter(name="path", type="string", required=True)],
            capabilities_required=[Capability.FILE_READ],
        )
    )
    tool = {
        "type": "function",
        "function": {
            "name": "fs_read",
            "parameters": {
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
            },
        },
    }

    def respond(self, url, payload):
        assert url.endswith("/responses")
        assert payload["reasoning"] == {"effort": "medium"}
        assert payload["tools"][0]["name"] == "fs_read"
        assert any("Read README.md" in m.get("content", "") for m in payload["input"])
        return {
            "status": "completed",
            "model": "gpt-6-luna",
            "output": [
                {"type": "reasoning", "summary": []},
                {
                    "type": "function_call",
                    "call_id": "read-1",
                    "name": "fs_read",
                    "arguments": '{"path":"README.md"}',
                    "status": "completed",
                },
            ],
        }

    monkeypatch.setattr(OpenAICompatibleProvider, "_post_json", respond)
    routed = RoutedOpenAIProvider(
        router=ModelRouter(
            ModelConfig(
                planner_provider_preset="openai_default",
                planner_model_id="gpt-6-luna",
                planner_endpoint_family="responses",
                planner_request_parameters={"reasoning_effort": "medium"},
            )
        )
    )
    planner = Planner(
        routed, PEP(PolicyBundle(default_require_confirmation=False), registry), max_retries=0
    )
    result = await planner.propose(
        "Read README.md",
        PolicyContext(
            capabilities={Capability.FILE_READ} if authorized else set(),
        ),
        tools=[tool],
    )
    assert len(result.evaluated) == 1
    action = result.evaluated[0]
    assert action.proposal.tool_name == "fs.read"
    assert action.proposal.arguments == {"path": "README.md"}
    assert (action.decision.kind == PEPDecisionKind.ALLOW) == authorized
    assert result.provider_response.model == "gpt-6-luna"
