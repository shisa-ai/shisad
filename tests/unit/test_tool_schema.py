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
    assert item["function"]["name"] == "fs_read"
    assert item["function"]["description"] == "Read files from allowlisted roots."
    assert item["function"]["parameters"]["type"] == "object"
    assert item["function"]["parameters"]["required"] == ["path"]


def test_tool_definition_json_schema_defaults_array_items_to_string() -> None:
    tool = ToolDefinition(
        name=ToolName("shell.exec"),
        description="Execute shell command",
        parameters=[ToolParameter(name="command", type="array", required=True)],
        capabilities_required=[Capability.SHELL_EXEC],
    )

    schema = tool.json_schema()
    assert schema["properties"]["command"]["type"] == "array"
    assert schema["properties"]["command"]["items"] == {"type": "string"}


def test_tool_definitions_to_openai_handles_empty_input() -> None:
    assert tool_definitions_to_openai([]) == []
