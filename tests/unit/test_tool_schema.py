"""Tool schema conversion checks."""

from __future__ import annotations

from shisad.core.tools.schema import (
    ToolDefinition,
    ToolParameter,
    tool_definitions_to_openai,
)
from shisad.core.types import Capability, ToolName


def test_tool_definitions_to_openai_converts_function_payload() -> None:
    tools = [
        ToolDefinition(
            name=ToolName("fs.read"),
            description="Read files from allowlisted roots.",
            parameters=[
                ToolParameter(name="path", type="string", required=True),
                ToolParameter(name="max_bytes", type="integer", required=False),
            ],
            capabilities_required=[Capability.FILE_READ],
        )
    ]

    payload = tool_definitions_to_openai(tools)

    assert len(payload) == 1
    item = payload[0]
    assert item["type"] == "function"
    assert item["function"]["name"] == "fs.read"
    assert item["function"]["description"] == "Read files from allowlisted roots."
    assert item["function"]["parameters"]["type"] == "object"
    assert item["function"]["parameters"]["required"] == ["path"]


def test_tool_definitions_to_openai_handles_empty_input() -> None:
    assert tool_definitions_to_openai([]) == []
