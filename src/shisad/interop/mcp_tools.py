"""MCP tool schema translation helpers."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from shisad.core.tools.schema import ToolDefinition, ToolParameter
from shisad.core.types import ToolName

_MCP_IDENTIFIER_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_MCP_PARAMETER_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]{0,63}$")


@dataclass(slots=True, frozen=True)
class McpDiscoveredTool:
    """Normalized MCP tool metadata used by the shisad bridge."""

    name: str
    description: str
    input_schema: dict[str, Any]


def normalize_mcp_identifier(value: str, *, field_name: str) -> str:
    """Normalize and validate an MCP server or tool identifier."""
    normalized = value.strip().lower()
    if not normalized or not _MCP_IDENTIFIER_RE.fullmatch(normalized):
        raise ValueError(
            f"MCP {field_name} must match ^[a-z0-9][a-z0-9._-]{{0,127}}$ after normalization"
        )
    return normalized


def mcp_runtime_tool_name(*, server_name: str, remote_tool_name: str) -> ToolName:
    """Build the canonical shisad runtime id for an MCP tool."""
    normalized_server = normalize_mcp_identifier(server_name, field_name="server name")
    normalized_tool = normalize_mcp_identifier(remote_tool_name, field_name="tool name")
    return ToolName(f"mcp.{normalized_server}.{normalized_tool}")


def _mapping(value: Any, *, field_name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"MCP {field_name} must be an object")
    return value


def _parameter_name(value: Any) -> str:
    parameter_name = str(value)
    if parameter_name != parameter_name.strip():
        raise ValueError("MCP tool parameter names must not include surrounding whitespace")
    if not _MCP_PARAMETER_NAME_RE.fullmatch(parameter_name):
        raise ValueError("MCP tool parameter names must match ^[A-Za-z_][A-Za-z0-9_-]{0,63}$")
    return parameter_name


def _tool_parameters(input_schema: Mapping[str, Any]) -> list[ToolParameter]:
    schema_type = str(input_schema.get("type", "object")).strip() or "object"
    if schema_type != "object":
        raise ValueError("MCP tool input schema must be an object schema")
    properties = _mapping(input_schema.get("properties", {}), field_name="tool properties")
    required = {
        str(item)
        for item in input_schema.get("required", [])
        if isinstance(item, str) and str(item).strip()
    }
    parameters: list[ToolParameter] = []
    for raw_name, raw_schema in properties.items():
        parameter_name = _parameter_name(raw_name)
        schema = _mapping(raw_schema, field_name=f"tool parameter '{parameter_name}'")
        parameter_type = str(schema.get("type", "string")).strip() or "string"
        items = schema.get("items", {})
        items_type: str | None = None
        if parameter_type == "array" and isinstance(items, Mapping):
            items_type = str(items.get("type", "string")).strip() or "string"
        enum_values = schema.get("enum")
        enum: list[Any] | None = None
        if isinstance(enum_values, list):
            enum = list(enum_values)
        parameters.append(
            ToolParameter(
                name=parameter_name,
                type=parameter_type,
                description=str(schema.get("description", "")).strip(),
                required=parameter_name in required,
                enum=enum,
                items_type=items_type,
            )
        )
    return parameters


def mcp_tool_to_registry_entry(mcp_tool: McpDiscoveredTool, server_name: str) -> ToolDefinition:
    """Translate a discovered MCP tool into a shisad ToolDefinition."""
    runtime_name = mcp_runtime_tool_name(server_name=server_name, remote_tool_name=mcp_tool.name)
    return ToolDefinition(
        name=runtime_name,
        description=str(mcp_tool.description).strip(),
        parameters=_tool_parameters(_mapping(mcp_tool.input_schema, field_name="input schema")),
        require_confirmation=True,
        registration_source="mcp",
        registration_source_id=normalize_mcp_identifier(server_name, field_name="server name"),
        upstream_tool_name=str(mcp_tool.name).strip(),
    )
