"""Tool registry.

Loads tool definitions from a trusted config directory, verifies schema
hashes on load, and provides lookup/validation methods.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import yaml

from shisad.core.tools.names import canonical_tool_name_typed
from shisad.core.tools.schema import ToolDefinition
from shisad.core.types import ToolName

logger = logging.getLogger(__name__)


class ToolRegistry:
    """Registry of available tools.

    Tools are trusted configuration — loaded from a designated directory,
    not discovered dynamically. Schema hashes are verified on load to
    detect tampering.
    """

    def __init__(self) -> None:
        self._tools: dict[ToolName, ToolDefinition] = {}
        self._expected_hashes: dict[ToolName, str] = {}

    def register(self, tool: ToolDefinition, expected_hash: str | None = None) -> None:
        """Register a tool definition.

        Args:
            tool: The tool definition to register.
            expected_hash: Expected schema hash. If provided, the tool's
                computed hash must match or registration fails.

        Raises:
            ValueError: If the hash doesn't match (tampering detected).
        """
        canonical_name = canonical_tool_name_typed(tool.name)
        canonical_tool = tool.model_copy(update={"name": canonical_name}, deep=True)

        if expected_hash is not None:
            actual_hash = canonical_tool.schema_hash()
            if actual_hash != expected_hash:
                raise ValueError(
                    f"Tool '{canonical_name}' schema hash mismatch: "
                    f"expected {expected_hash[:12]}…, got {actual_hash[:12]}…"
                )
            self._expected_hashes[canonical_name] = expected_hash

        self._tools[canonical_name] = canonical_tool
        logger.debug("Registered tool: %s", canonical_name)

    def get_tool(self, name: ToolName) -> ToolDefinition | None:
        """Get a tool definition by name."""
        canonical_name = canonical_tool_name_typed(name)
        tool = self._tools.get(canonical_name)
        if tool is None:
            return None
        return tool.model_copy(deep=True)

    def list_tools(self) -> list[ToolDefinition]:
        """List all registered tools."""
        return [tool.model_copy(deep=True) for tool in self._tools.values()]

    def has_tool(self, name: ToolName) -> bool:
        """Check if a tool is registered."""
        return canonical_tool_name_typed(name) in self._tools

    def unregister(self, name: ToolName) -> bool:
        """Remove a tool definition if present."""
        canonical_name = canonical_tool_name_typed(name)
        removed = self._tools.pop(canonical_name, None)
        self._expected_hashes.pop(canonical_name, None)
        return removed is not None

    def validate_call(self, name: ToolName, arguments: dict[str, Any]) -> list[str]:
        """Validate a tool call's arguments against the tool's schema.

        Returns a list of validation errors (empty = valid).
        """
        canonical_name = canonical_tool_name_typed(name)
        tool = self._tools.get(canonical_name)
        if tool is None:
            return [f"Unknown tool: {canonical_name}"]

        errors: list[str] = []
        schema = tool.json_schema()
        properties = schema.get("properties", {})
        required = set(schema.get("required", []))

        # Check for missing required arguments
        for req in required:
            if req not in arguments:
                errors.append(f"Missing required argument: {req}")

        # Check for extra arguments (additionalProperties: false)
        for key in arguments:
            if key not in properties:
                errors.append(f"Unexpected argument: {key}")

        # Basic type checking
        for key, value in arguments.items():
            if key not in properties:
                continue
            expected_type = properties[key].get("type")
            if expected_type is not None and not self._check_type(value, expected_type):
                errors.append(
                    f"Argument '{key}': expected type '{expected_type}', "
                    f"got '{type(value).__name__}'"
                )

            # Enum validation
            allowed = properties[key].get("enum")
            if allowed is not None and value not in allowed:
                errors.append(f"Argument '{key}': value '{value}' not in {allowed}")

        return errors

    def load_from_directory(self, tools_dir: Path) -> int:
        """Load tool definitions from YAML/JSON files in a directory.

        Returns the number of tools loaded.
        """
        if not tools_dir.is_dir():
            logger.warning("Tools directory not found: %s", tools_dir)
            return 0

        count = 0
        for path in sorted(tools_dir.iterdir()):
            if path.suffix in (".yaml", ".yml"):
                data = yaml.safe_load(path.read_text())
            elif path.suffix == ".json":
                data = json.loads(path.read_text())
            else:
                continue

            if data is None:
                continue

            tool = ToolDefinition.model_validate(data)
            expected_hash = data.get("schema_hash")
            self.register(tool, expected_hash=expected_hash)
            count += 1

        logger.info("Loaded %d tools from %s", count, tools_dir)
        return count

    @staticmethod
    def _check_type(value: Any, expected: str) -> bool:
        """Basic JSON Schema type check."""
        type_map: dict[str, type | tuple[type, ...]] = {
            "string": str,
            "integer": int,
            "number": (int, float),
            "boolean": bool,
            "object": dict,
            "array": list,
        }
        expected_type = type_map.get(expected)
        if expected_type is None:
            return True  # Unknown type, don't reject
        return isinstance(value, expected_type)
