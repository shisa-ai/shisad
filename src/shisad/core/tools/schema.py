"""Tool schema definitions.

Tools are trusted configuration — their definitions are loaded from
a designated config directory and verified via schema hashes. No dynamic
tool discovery from the model or data plane.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from pydantic import BaseModel, Field

from shisad.core.types import Capability, ToolName


class ToolParameter(BaseModel):
    """A single parameter in a tool's schema."""

    name: str
    type: str  # JSON Schema type: "string", "integer", "boolean", "object", "array"
    description: str = ""
    required: bool = True
    enum: list[str] | None = None
    items_type: str | None = None
    semantic_type: str | None = None
    items_semantic_type: str | None = None

    model_config = {"frozen": True}


class ToolDefinition(BaseModel):
    """Definition of a tool available to the agent.

    Tool definitions are trusted config — they specify what the tool does,
    what parameters it accepts, and what capabilities it requires.
    """

    name: ToolName
    description: str
    parameters: list[ToolParameter] = Field(default_factory=list)
    capabilities_required: list[Capability] = Field(default_factory=list)
    destinations: list[str] = Field(default_factory=list)
    require_confirmation: bool = False
    sandbox_type: str | None = None

    model_config = {"frozen": True}

    def schema_hash(self) -> str:
        """Compute a deterministic hash of the tool schema for integrity verification."""
        canonical = json.dumps(
            {
                "name": self.name,
                "description": self.description,
                "parameters": [p.model_dump() for p in self.parameters],
                "capabilities_required": sorted(self.capabilities_required),
                "destinations": sorted(self.destinations),
                "require_confirmation": self.require_confirmation,
                "sandbox_type": self.sandbox_type or "",
            },
            sort_keys=True,
        )
        return hashlib.sha256(canonical.encode()).hexdigest()

    def json_schema(self) -> dict[str, Any]:
        """Generate a JSON Schema representation for argument validation."""
        properties: dict[str, Any] = {}
        required_fields: list[str] = []

        for param in self.parameters:
            prop: dict[str, Any] = {
                "type": param.type,
                "description": param.description,
            }
            if param.type == "array":
                # OpenAI function-parameter schemas require `items` for array fields.
                prop["items"] = {"type": param.items_type or "string"}
                if param.items_semantic_type is not None:
                    prop["items"]["x-shisad-semantic-type"] = param.items_semantic_type
            if param.enum is not None:
                prop["enum"] = param.enum
            if param.semantic_type is not None:
                prop["x-shisad-semantic-type"] = param.semantic_type
            properties[param.name] = prop
            if param.required:
                required_fields.append(param.name)

        return {
            "type": "object",
            "properties": properties,
            "required": required_fields,
            "additionalProperties": False,
        }


_OPENAI_FUNCTION_NAME_RE = re.compile(r"^[a-zA-Z0-9_-]+$")


def openai_function_name(tool_name: str) -> str:
    """Return an OpenAI-compliant function name for a canonical tool id.

    OpenAI function names must match ``^[a-zA-Z0-9_-]+$``. Canonical shisad
    tool ids use dotted names, so we map dots/hyphens to underscores.
    """

    candidate = tool_name.strip()
    if _OPENAI_FUNCTION_NAME_RE.fullmatch(candidate):
        return candidate
    normalized = candidate.replace(".", "_").replace("-", "_")
    return normalized


def _openai_function_name(tool_name: str) -> str:
    return openai_function_name(tool_name)


def tool_definitions_to_openai(tools: list[ToolDefinition]) -> list[dict[str, Any]]:
    """Convert tool definitions to OpenAI-compatible `tools` payload format."""
    payload: list[dict[str, Any]] = []
    for tool in tools:
        payload.append(
            {
                "type": "function",
                "function": {
                    "name": openai_function_name(str(tool.name)),
                    "description": tool.description,
                    "parameters": tool.json_schema(),
                },
            }
        )
    return payload
