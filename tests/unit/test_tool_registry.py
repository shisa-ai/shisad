"""Validation behavior for runtime tool schemas."""

from __future__ import annotations

from shisad.core.tools.registry import ToolRegistry
from shisad.core.tools.schema import ToolDefinition, ToolParameter
from shisad.core.types import ToolName


def _registry_with_note_create() -> ToolRegistry:
    registry = ToolRegistry()
    registry.register(
        ToolDefinition(
            name=ToolName("note.create"),
            description="Store a note.",
            parameters=[
                ToolParameter(name="content", type="string", required=True),
                ToolParameter(name="key", type="string", required=False),
            ],
        )
    )
    return registry


def test_tool_registry_allows_null_for_optional_argument() -> None:
    registry = _registry_with_note_create()

    assert (
        registry.validate_call(
            ToolName("note.create"),
            {"content": "remember to buy groceries", "key": None},
        )
        == []
    )


def test_tool_registry_rejects_null_for_required_argument() -> None:
    registry = _registry_with_note_create()

    errors = registry.validate_call(
        ToolName("note.create"),
        {"content": None},
    )

    assert errors == ["Missing required argument: content"]


def test_tool_registry_resolves_provider_alias_to_registered_tool() -> None:
    registry = ToolRegistry()
    registry.register(
        ToolDefinition(
            name=ToolName("mcp.docs.lookup-doc"),
            description="Lookup remote docs.",
            parameters=[ToolParameter(name="query", type="string", required=True)],
            registration_source="mcp",
            registration_source_id="docs",
            upstream_tool_name="lookup-doc",
        )
    )

    resolved = registry.get_tool(ToolName("mcp_docs_lookup_doc"))

    assert resolved is not None
    assert resolved.name == ToolName("mcp.docs.lookup-doc")
    assert registry.validate_call(ToolName("mcp_docs_lookup_doc"), {"query": "roadmap"}) == []
