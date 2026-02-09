"""Tool schema definitions.

Tools are trusted configuration — their definitions are loaded from
a designated config directory and verified via schema hashes. No dynamic
tool discovery from the model or data plane.
"""

from __future__ import annotations

import hashlib
import json
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

    model_config = {"frozen": True}

    def schema_hash(self) -> str:
        """Compute a deterministic hash of the tool schema for integrity verification."""
        canonical = json.dumps(
            {
                "name": self.name,
                "parameters": [p.model_dump() for p in self.parameters],
                "capabilities_required": sorted(self.capabilities_required),
                "destinations": sorted(self.destinations),
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
            if param.enum is not None:
                prop["enum"] = param.enum
            properties[param.name] = prop
            if param.required:
                required_fields.append(param.name)

        return {
            "type": "object",
            "properties": properties,
            "required": required_fields,
            "additionalProperties": False,
        }
