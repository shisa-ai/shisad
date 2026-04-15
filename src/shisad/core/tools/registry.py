"""Tool registry.

Loads locally trusted tool definitions, accepts explicitly-labeled external
registrations, verifies schema hashes when provided, and rejects shadowing.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

from shisad.core.tools.names import canonical_tool_name, canonical_tool_name_typed
from shisad.core.tools.schema import ToolDefinition, openai_function_name
from shisad.core.types import ToolName

logger = logging.getLogger(__name__)

_OPAQUE_HANDLE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_CREDENTIAL_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_PATH_SEGMENT_SPLIT_RE = re.compile(r"[\\/]+")
_INSTRUCTION_PREFIXES = {
    "please",
    "read",
    "write",
    "edit",
    "open",
    "fetch",
    "review",
    "summarize",
    "run",
    "execute",
    "use",
    "visit",
    "send",
    "call",
    "search",
}


def _normalized_semantic_candidate(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    candidate = value.strip()
    if candidate != value or not candidate:
        return None
    if any(token in candidate for token in ("\x00", "\n", "\r", "\t")):
        return None
    return candidate


def _looks_like_instructional_text(candidate: str) -> bool:
    tokens = candidate.split()
    if len(tokens) < 3:
        return False
    first = tokens[0].lower().rstrip(":,.!?")
    if first in _INSTRUCTION_PREFIXES:
        return True
    if first == "please" and len(tokens) >= 2:
        second = tokens[1].lower().rstrip(":,.!?")
        if second in _INSTRUCTION_PREFIXES:
            return True
    return all(re.fullmatch(r"[A-Za-z]+", token) for token in tokens[:2])


def is_valid_semantic_value(value: Any, expected: str) -> bool:
    candidate = _normalized_semantic_candidate(value)
    if candidate is None:
        return False
    if expected == "url":
        if any(char.isspace() for char in candidate):
            return False
        parsed = urlparse(candidate)
        return parsed.scheme in {"http", "https"} and bool(parsed.hostname) and bool(parsed.netloc)
    if expected == "workspace_path":
        if _looks_like_instructional_text(candidate):
            return False
        segments = _PATH_SEGMENT_SPLIT_RE.split(candidate)
        for index, segment in enumerate(segments):
            if segment == "" and index in {0, len(segments) - 1}:
                continue
            if not segment or segment.strip() != segment:
                return False
            if segment == "..":
                return False
        return True
    if expected == "command_token":
        if any(char.isspace() for char in candidate):
            return False
        return not _looks_like_instructional_text(candidate)
    if expected == "credential_ref":
        return bool(_CREDENTIAL_REF_RE.fullmatch(candidate))
    if expected in {"evidence_ref", "artifact_ref", "thread_id"}:
        return bool(_OPAQUE_HANDLE_RE.fullmatch(candidate))
    if expected == "recipient":
        # Channel recipients span room ids, email addresses, and webhook-like
        # handles today, so keep this intentionally minimal until a dedicated
        # address normalizer exists.
        return True
    if expected == "email_address":
        return bool(re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", candidate))
    return True


class ToolRegistry:
    """Registry of available tools.

    Tools are trusted configuration — loaded from a designated directory,
    not discovered dynamically. Schema hashes are verified on load to
    detect tampering.
    """

    def __init__(self) -> None:
        self._tools: dict[ToolName, ToolDefinition] = {}
        self._expected_hashes: dict[ToolName, str] = {}
        self._provider_aliases: dict[str, ToolName] = {}

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
        canonical_tool = tool.model_copy(
            update={
                "name": canonical_name,
                "registration_source": str(tool.registration_source).strip().lower() or "local",
                "registration_source_id": str(tool.registration_source_id).strip().lower(),
                "upstream_tool_name": str(tool.upstream_tool_name).strip(),
            },
            deep=True,
        )
        existing = self._tools.get(canonical_name)
        if existing is not None and existing != canonical_tool:
            raise ValueError(f"Tool '{canonical_name}' is already registered")

        provider_alias = openai_function_name(str(canonical_name))
        alias_owner = self._provider_aliases.get(provider_alias)
        if alias_owner is not None and alias_owner != canonical_name:
            raise ValueError(
                "Tool "
                f"'{canonical_name}' provider alias collision with '{alias_owner}' "
                f"({provider_alias})"
            )

        if expected_hash is not None:
            actual_hash = canonical_tool.schema_hash()
            if actual_hash != expected_hash:
                raise ValueError(
                    f"Tool '{canonical_name}' schema hash mismatch: "
                    f"expected {expected_hash[:12]}…, got {actual_hash[:12]}…"
                )
            self._expected_hashes[canonical_name] = expected_hash

        self._tools[canonical_name] = canonical_tool
        self._provider_aliases[provider_alias] = canonical_name
        logger.debug("Registered tool: %s", canonical_name)

    def resolve_name(self, name: ToolName | str, *, warn_on_alias: bool = True) -> ToolName | None:
        """Resolve a canonical or provider-alias tool name to the registered id."""
        candidate = canonical_tool_name(str(name), warn_on_alias=warn_on_alias)
        if not candidate:
            return None
        canonical_name = ToolName(candidate)
        if canonical_name in self._tools:
            return canonical_name
        return self._provider_aliases.get(candidate)

    def get_tool(self, name: ToolName) -> ToolDefinition | None:
        """Get a tool definition by name."""
        canonical_name = self.resolve_name(name)
        if canonical_name is None:
            return None
        tool = self._tools.get(canonical_name)
        if tool is None:
            return None
        return tool.model_copy(deep=True)

    def list_tools(self) -> list[ToolDefinition]:
        """List all registered tools."""
        return [tool.model_copy(deep=True) for tool in self._tools.values()]

    def has_tool(self, name: ToolName) -> bool:
        """Check if a tool is registered."""
        return self.resolve_name(name) is not None

    def unregister(self, name: ToolName) -> bool:
        """Remove a tool definition if present."""
        canonical_name = self.resolve_name(name)
        if canonical_name is None:
            return False
        removed = self._tools.pop(canonical_name, None)
        self._expected_hashes.pop(canonical_name, None)
        provider_alias = openai_function_name(str(canonical_name))
        if self._provider_aliases.get(provider_alias) == canonical_name:
            self._provider_aliases.pop(provider_alias, None)
        return removed is not None

    def validate_call(self, name: ToolName, arguments: dict[str, Any]) -> list[str]:
        """Validate a tool call's arguments against the tool's schema.

        Returns a list of validation errors (empty = valid).
        """
        canonical_name = self.resolve_name(name)
        if canonical_name is None:
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
            if req not in arguments or arguments.get(req) is None:
                errors.append(f"Missing required argument: {req}")

        # Check for extra arguments (additionalProperties: false)
        for key in arguments:
            if key not in properties:
                errors.append(f"Unexpected argument: {key}")

        # Basic type checking
        for key, value in arguments.items():
            if key not in properties:
                continue
            if value is None:
                continue
            expected_type = properties[key].get("type")
            if expected_type is not None and not self._check_type(value, expected_type):
                errors.append(
                    f"Argument '{key}': expected type '{expected_type}', "
                    f"got '{type(value).__name__}'"
                )
                continue

            semantic_type = properties[key].get("x-shisad-semantic-type")
            if semantic_type is not None and not self._check_semantic_value(
                value,
                str(semantic_type),
            ):
                errors.append(f"Argument '{key}': expected validated atom '{semantic_type}'")
                continue

            item_schema = properties[key].get("items", {})
            item_type = item_schema.get("type")
            if item_type is not None and isinstance(value, list):
                invalid_item_type = next(
                    (
                        type(item).__name__
                        for item in value
                        if not self._check_type(item, str(item_type))
                    ),
                    None,
                )
                if invalid_item_type is not None:
                    errors.append(
                        f"Argument '{key}': expected items of type '{item_type}', "
                        f"got '{invalid_item_type}'"
                    )
                    continue
            items_semantic_type = item_schema.get("x-shisad-semantic-type")
            if (
                items_semantic_type is not None
                and isinstance(value, list)
                and not all(
                    self._check_semantic_value(item, str(items_semantic_type)) for item in value
                )
            ):
                errors.append(f"Argument '{key}': expected validated atoms '{items_semantic_type}'")
                continue

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

            external_metadata_keys = {
                "registration_source",
                "registration_source_id",
                "upstream_tool_name",
            }
            declared_external_metadata = sorted(
                key for key in external_metadata_keys if key in data
            )
            if declared_external_metadata:
                raise ValueError(
                    "Local tool definitions must not declare external registration metadata: "
                    + ", ".join(declared_external_metadata)
                )

            tool = ToolDefinition.model_validate(data)
            expected_hash = data.get("schema_hash")
            self.register(tool, expected_hash=expected_hash)
            count += 1

        logger.info("Loaded %d tools from %s", count, tools_dir)
        return count

    @staticmethod
    def _check_type(value: Any, expected: str) -> bool:
        """Basic JSON Schema type check."""
        if expected == "integer":
            return isinstance(value, int) and not isinstance(value, bool)
        if expected == "number":
            return isinstance(value, (int, float)) and not isinstance(value, bool)
        type_map: dict[str, type | tuple[type, ...]] = {
            "string": str,
            "boolean": bool,
            "object": dict,
            "array": list,
        }
        expected_type = type_map.get(expected)
        if expected_type is None:
            return True  # Unknown type, don't reject
        return isinstance(value, expected_type)

    @staticmethod
    def _check_semantic_value(value: Any, expected: str) -> bool:
        return is_valid_semantic_value(value, expected)
