"""Regression coverage for planner tool-context trust normalization."""

from __future__ import annotations

from shisad.core.tools.schema import ToolDefinition, ToolParameter
from shisad.core.types import Capability, ToolName
from shisad.daemon.handlers._impl import _build_planner_tool_context


def test_m6_planner_tool_context_normalizes_trust_level_casing() -> None:
    tool = ToolDefinition(
        name=ToolName("web_search"),
        description="Search backend",
        parameters=[ToolParameter(name="query", type="string", required=True)],
        capabilities_required=[Capability.HTTP_REQUEST],
    )

    # Mixed-case trusted identity should receive trusted-context detail.
    context = _build_planner_tool_context(
        registry_tools=[tool],
        capabilities=set(),
        tool_allowlist=None,
        trust_level="Trusted",
    )
    assert "Enabled tools: none" in context
    assert "Unavailable tools in this session:" in context
