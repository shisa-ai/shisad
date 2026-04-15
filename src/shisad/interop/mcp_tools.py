"""MCP tool schema translation helpers."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from shisad.core.tools.schema import ToolDefinition, ToolParameter
from shisad.core.types import ToolName

_MCP_IDENTIFIER_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_MCP_PARAMETER_NAME_MAX_LENGTH = 256
_MCP_PARAMETER_NAME_FORBIDDEN_CHARS = frozenset({'"', "'", "`", "<", ">", "{", "}", "\\"})
_MCP_ENUM_MAX_VALUES = 16
_MCP_ENUM_MAX_SERIALIZED_BYTES = 256
_MCP_ENUM_STRING_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,23}$")
_MCP_ENUM_BLOCKED_TOKENS = frozenset(
    {
        "exfil",
        "exfiltrate",
        "exfiltration",
        "ignore",
        "instruction",
        "instructions",
        "override",
        "prompt",
        "prompts",
        "secret",
        "secrets",
    }
)
_MCP_ENUM_TOKEN_SPLIT_RE = re.compile(r"[-_]+")
_ALLOWED_MCP_JSON_SCHEMA_TYPES = frozenset(
    {"array", "boolean", "integer", "number", "object", "string"}
)


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
    if not parameter_name:
        raise ValueError("MCP tool parameter names must not be empty")
    if parameter_name != parameter_name.strip():
        raise ValueError("MCP tool parameter names must not include surrounding whitespace")
    if len(parameter_name) > _MCP_PARAMETER_NAME_MAX_LENGTH:
        raise ValueError(
            f"MCP tool parameter names must be at most {_MCP_PARAMETER_NAME_MAX_LENGTH} characters"
        )
    if any(not char.isprintable() or char.isspace() for char in parameter_name):
        raise ValueError(
            "MCP tool parameter names must not contain whitespace or control characters"
        )
    if any(char in _MCP_PARAMETER_NAME_FORBIDDEN_CHARS for char in parameter_name):
        raise ValueError(
            "MCP tool parameter names must not contain quotes, backslashes, braces, "
            "angle brackets, or backticks"
        )
    return parameter_name


def _json_schema_type(value: Any, *, field_name: str, default: str) -> str:
    raw = "" if value is None else str(value)
    schema_type = raw.strip().lower()
    if not schema_type:
        return default
    if schema_type not in _ALLOWED_MCP_JSON_SCHEMA_TYPES:
        allowed = ", ".join(sorted(_ALLOWED_MCP_JSON_SCHEMA_TYPES))
        raise ValueError(f"MCP {field_name} must declare one of: {allowed}")
    return schema_type


def _required_fields(input_schema: Mapping[str, Any]) -> set[str]:
    raw_required = input_schema.get("required", [])
    if raw_required is None:
        return set()
    if not isinstance(raw_required, list):
        raise ValueError("MCP tool required must be a list of non-empty strings")
    required: set[str] = set()
    for item in raw_required:
        if not isinstance(item, str) or not item.strip():
            raise ValueError("MCP tool required must be a list of non-empty strings")
        required.add(_parameter_name(item))
    return required


def _enum_string(value: str, *, field_name: str) -> str:
    enum_value = value.strip()
    lowered = enum_value.lower()
    if not enum_value or enum_value != value or not _MCP_ENUM_STRING_RE.fullmatch(enum_value):
        raise ValueError(
            f"MCP {field_name} enum string values must match ^[A-Za-z0-9][A-Za-z0-9_-]{{0,23}}$"
        )
    tokens = [token for token in _MCP_ENUM_TOKEN_SPLIT_RE.split(lowered) if token]
    if any(token in _MCP_ENUM_BLOCKED_TOKENS for token in tokens):
        raise ValueError(
            f"MCP {field_name} enum string values must not contain instruction-like tokens"
        )
    return enum_value


def _enum_values(value: Any, *, field_name: str) -> list[Any] | None:
    if value is None:
        return None
    if not isinstance(value, list):
        raise ValueError(f"MCP {field_name} enum must be a list")
    if len(value) > _MCP_ENUM_MAX_VALUES:
        raise ValueError(
            f"MCP {field_name} enum must contain at most {_MCP_ENUM_MAX_VALUES} values"
        )
    normalized: list[Any] = []
    for item in value:
        if isinstance(item, str):
            normalized.append(_enum_string(item, field_name=field_name))
            continue
        if item is None or isinstance(item, (bool, int, float)):
            normalized.append(item)
            continue
        raise ValueError(f"MCP {field_name} enum values must be scalar JSON values")
    try:
        serialized = json.dumps(
            normalized,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError) as exc:
        raise ValueError(f"MCP {field_name} enum values must be scalar JSON values") from exc
    if len(serialized) > _MCP_ENUM_MAX_SERIALIZED_BYTES:
        raise ValueError(
            f"MCP {field_name} enum must serialize to at most "
            f"{_MCP_ENUM_MAX_SERIALIZED_BYTES} bytes"
        )
    return normalized


def _tool_parameters(input_schema: Mapping[str, Any]) -> list[ToolParameter]:
    schema_type = _json_schema_type(
        input_schema.get("type"),
        field_name="input schema type",
        default="object",
    )
    if schema_type != "object":
        raise ValueError("MCP tool input schema must be an object schema")
    properties = _mapping(input_schema.get("properties", {}), field_name="tool properties")
    required = _required_fields(input_schema)
    parameters: list[ToolParameter] = []
    for raw_name, raw_schema in properties.items():
        parameter_name = _parameter_name(raw_name)
        schema = _mapping(raw_schema, field_name=f"tool parameter '{parameter_name}'")
        parameter_type = _json_schema_type(
            schema.get("type"),
            field_name=f"tool parameter '{parameter_name}' type",
            default="string",
        )
        items_type: str | None = None
        if parameter_type == "array":
            raw_items = schema.get("items", {})
            items = (
                {}
                if raw_items in ({}, None)
                else _mapping(raw_items, field_name=f"tool parameter '{parameter_name}' items")
            )
            items_type = _json_schema_type(
                items.get("type"),
                field_name=f"tool parameter '{parameter_name}' items.type",
                default="string",
            )
        enum = _enum_values(schema.get("enum"), field_name=f"tool parameter '{parameter_name}'")
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
    parameter_names = {parameter.name for parameter in parameters}
    unknown_required = sorted(required - parameter_names)
    if unknown_required:
        raise ValueError("MCP tool required entries must match declared property names")
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
