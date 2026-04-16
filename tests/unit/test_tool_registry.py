"""Validation behavior for runtime tool schemas."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from shisad.core.tools.registry import ToolRegistry, is_valid_semantic_value
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


# --- Semantic-value validation (is_valid_semantic_value) ---


def test_is_valid_semantic_value_url_accepts_http_and_https_with_host() -> None:
    assert is_valid_semantic_value("https://example.com/path", "url") is True
    assert is_valid_semantic_value("http://example.com", "url") is True


def test_is_valid_semantic_value_url_rejects_non_http_schemes_and_bare_host() -> None:
    assert is_valid_semantic_value("ftp://example.com/file", "url") is False
    assert is_valid_semantic_value("file:///etc/passwd", "url") is False
    assert is_valid_semantic_value("javascript:alert(1)", "url") is False
    assert is_valid_semantic_value("example.com", "url") is False
    assert is_valid_semantic_value("https:///no-host", "url") is False


def test_is_valid_semantic_value_url_rejects_whitespace_and_control_chars() -> None:
    assert is_valid_semantic_value("https://example.com /path", "url") is False
    assert is_valid_semantic_value(" https://example.com", "url") is False
    assert is_valid_semantic_value("https://example.com\npath", "url") is False


def test_is_valid_semantic_value_workspace_path_rejects_traversal_and_instructions() -> None:
    assert is_valid_semantic_value("src/shisad/core/tools/registry.py", "workspace_path") is True
    assert is_valid_semantic_value("/absolute/path/file.txt", "workspace_path") is True
    assert is_valid_semantic_value("../etc/passwd", "workspace_path") is False
    assert is_valid_semantic_value("src/../../etc/passwd", "workspace_path") is False
    assert is_valid_semantic_value("please read my homework notes", "workspace_path") is False


def test_is_valid_semantic_value_workspace_path_rejects_whitespace_in_segment() -> None:
    assert is_valid_semantic_value("src/ registry.py", "workspace_path") is False
    assert is_valid_semantic_value("src/registry.py ", "workspace_path") is False


def test_is_valid_semantic_value_command_token_rejects_whitespace_and_instructions() -> None:
    assert is_valid_semantic_value("python3", "command_token") is True
    assert is_valid_semantic_value("python -c 'import sys'", "command_token") is False
    assert is_valid_semantic_value("execute a shell command now", "command_token") is False


def test_is_valid_semantic_value_credential_ref_enforces_opaque_handle() -> None:
    assert is_valid_semantic_value("mail_read", "credential_ref") is True
    assert is_valid_semantic_value("api.token:v1", "credential_ref") is True
    assert is_valid_semantic_value("bad slash/ref", "credential_ref") is False
    assert is_valid_semantic_value("", "credential_ref") is False
    assert is_valid_semantic_value("a" * 200, "credential_ref") is False


def test_is_valid_semantic_value_email_address_enforces_local_at_host_dot_host() -> None:
    assert is_valid_semantic_value("alice@example.com", "email_address") is True
    assert is_valid_semantic_value("alice@example", "email_address") is False
    assert is_valid_semantic_value("alice@@example.com", "email_address") is False
    assert is_valid_semantic_value("alice example.com", "email_address") is False


def test_is_valid_semantic_value_rejects_non_string_and_leading_whitespace() -> None:
    assert is_valid_semantic_value(12345, "url") is False
    assert is_valid_semantic_value(None, "credential_ref") is False
    assert is_valid_semantic_value("  spaced  ", "credential_ref") is False


def test_is_valid_semantic_value_unknown_expected_type_accepts_value() -> None:
    # Unknown semantic types default to accept (don't block unknown atoms).
    assert is_valid_semantic_value("anything-goes", "future_type") is True


# --- validate_call: semantic types, enums, array items ---


def test_validate_call_rejects_invalid_url_semantic_value() -> None:
    registry = ToolRegistry()
    registry.register(
        ToolDefinition(
            name=ToolName("web.fetch"),
            description="Fetch URL.",
            parameters=[
                ToolParameter(name="url", type="string", required=True, semantic_type="url"),
            ],
        )
    )

    errors = registry.validate_call(ToolName("web.fetch"), {"url": "not a url"})

    assert any("expected validated atom 'url'" in err for err in errors)


def test_validate_call_rejects_array_items_with_invalid_semantic_values() -> None:
    registry = ToolRegistry()
    registry.register(
        ToolDefinition(
            name=ToolName("web.batch_fetch"),
            description="Fetch multiple URLs.",
            parameters=[
                ToolParameter(
                    name="urls",
                    type="array",
                    required=True,
                    items_type="string",
                    items_semantic_type="url",
                ),
            ],
        )
    )

    errors = registry.validate_call(
        ToolName("web.batch_fetch"),
        {"urls": ["https://ok.example.com", "ftp://bad"]},
    )

    assert any("expected validated atoms 'url'" in err for err in errors)


def test_validate_call_rejects_array_items_with_wrong_primitive_type() -> None:
    registry = ToolRegistry()
    registry.register(
        ToolDefinition(
            name=ToolName("shell.exec"),
            description="Execute command.",
            parameters=[
                ToolParameter(name="command", type="array", required=True, items_type="string"),
            ],
        )
    )

    errors = registry.validate_call(
        ToolName("shell.exec"),
        {"command": ["ls", 42]},
    )

    assert any("expected items of type 'string'" in err for err in errors)


def test_validate_call_rejects_enum_value_not_in_allowed_list() -> None:
    registry = ToolRegistry()
    registry.register(
        ToolDefinition(
            name=ToolName("file.read"),
            description="Read file.",
            parameters=[
                ToolParameter(name="mode", type="string", required=True, enum=["read", "binary"]),
            ],
        )
    )

    errors = registry.validate_call(ToolName("file.read"), {"mode": "write"})

    assert any("not in ['read', 'binary']" in err for err in errors)


def test_validate_call_rejects_unknown_tool() -> None:
    registry = ToolRegistry()

    errors = registry.validate_call(ToolName("nonexistent.tool"), {})

    assert errors and all("Unknown tool" in err for err in errors)


def test_validate_call_rejects_extra_arguments() -> None:
    registry = _registry_with_note_create()

    errors = registry.validate_call(
        ToolName("note.create"),
        {"content": "note", "surprise": "extra"},
    )

    assert any("Unexpected argument: surprise" in err for err in errors)


def test_validate_call_check_type_distinguishes_bool_from_integer_and_number() -> None:
    registry = ToolRegistry()
    registry.register(
        ToolDefinition(
            name=ToolName("counter.inc"),
            description="Increment counter.",
            parameters=[
                ToolParameter(name="delta", type="integer", required=True),
                ToolParameter(name="scale", type="number", required=False),
            ],
        )
    )

    assert registry.validate_call(ToolName("counter.inc"), {"delta": 1, "scale": 1.5}) == []

    bool_errors = registry.validate_call(ToolName("counter.inc"), {"delta": True})
    assert any("expected type 'integer'" in err for err in bool_errors)

    bool_number_errors = registry.validate_call(
        ToolName("counter.inc"), {"delta": 1, "scale": True}
    )
    assert any("expected type 'number'" in err for err in bool_number_errors)


# --- Registry: hash verification, re-registration, unregister, alias collisions ---


def test_register_rejects_schema_hash_mismatch() -> None:
    registry = ToolRegistry()
    tool = ToolDefinition(
        name=ToolName("note.create"),
        description="Store a note.",
        parameters=[ToolParameter(name="content", type="string", required=True)],
    )

    with pytest.raises(ValueError, match="schema hash mismatch"):
        registry.register(tool, expected_hash="0" * 64)


def test_register_accepts_matching_schema_hash() -> None:
    registry = ToolRegistry()
    tool = ToolDefinition(
        name=ToolName("note.create"),
        description="Store a note.",
        parameters=[ToolParameter(name="content", type="string", required=True)],
    )

    registry.register(tool, expected_hash=tool.schema_hash())

    assert registry.has_tool(ToolName("note.create"))


def test_register_is_idempotent_for_identical_tool_definitions() -> None:
    registry = ToolRegistry()
    tool = ToolDefinition(
        name=ToolName("note.create"),
        description="Store a note.",
        parameters=[ToolParameter(name="content", type="string", required=True)],
    )

    registry.register(tool)
    registry.register(tool)  # must not raise

    assert len(registry.list_tools()) == 1


def test_register_rejects_conflicting_re_registration_with_different_description() -> None:
    registry = ToolRegistry()
    registry.register(
        ToolDefinition(
            name=ToolName("note.create"),
            description="Store a note.",
            parameters=[ToolParameter(name="content", type="string", required=True)],
        )
    )

    with pytest.raises(ValueError, match="already registered"):
        registry.register(
            ToolDefinition(
                name=ToolName("note.create"),
                description="Store a DIFFERENT note.",
                parameters=[ToolParameter(name="content", type="string", required=True)],
            )
        )


def test_register_rejects_provider_alias_collision_with_distinct_canonical_id() -> None:
    registry = ToolRegistry()
    registry.register(
        ToolDefinition(
            name=ToolName("mcp.docs.lookup-doc"),
            description="Local docs.",
            parameters=[ToolParameter(name="q", type="string", required=True)],
            registration_source="mcp",
            registration_source_id="docs",
            upstream_tool_name="lookup-doc",
        )
    )

    with pytest.raises(ValueError, match="provider alias collision"):
        registry.register(
            ToolDefinition(
                name=ToolName("mcp_docs_lookup_doc"),
                description="A different canonical tool id that shares the provider alias.",
                parameters=[ToolParameter(name="q", type="string", required=True)],
            )
        )


def test_unregister_removes_tool_and_frees_provider_alias() -> None:
    registry = ToolRegistry()
    registry.register(
        ToolDefinition(
            name=ToolName("mcp.docs.lookup-doc"),
            description="Lookup remote docs.",
            parameters=[ToolParameter(name="q", type="string", required=True)],
            registration_source="mcp",
            registration_source_id="docs",
            upstream_tool_name="lookup-doc",
        )
    )

    assert registry.unregister(ToolName("mcp.docs.lookup-doc")) is True
    assert registry.has_tool(ToolName("mcp.docs.lookup-doc")) is False
    assert registry.resolve_name(ToolName("mcp_docs_lookup_doc")) is None

    # Provider alias must be reusable after unregister.
    registry.register(
        ToolDefinition(
            name=ToolName("mcp_docs_lookup_doc"),
            description="Replacement with the canonical-id form.",
            parameters=[ToolParameter(name="q", type="string", required=True)],
        )
    )
    assert registry.has_tool(ToolName("mcp_docs_lookup_doc"))


def test_unregister_returns_false_for_unknown_tool() -> None:
    registry = ToolRegistry()

    assert registry.unregister(ToolName("nonexistent.tool")) is False


# --- load_from_directory: YAML/JSON, metadata rejection, hash verification ---


def test_load_from_directory_loads_yaml_and_json_files(tmp_path: Path) -> None:
    tools_dir = tmp_path / "tools"
    tools_dir.mkdir()
    (tools_dir / "note.yaml").write_text(
        yaml.safe_dump(
            {
                "name": "note.create",
                "description": "Store a note.",
                "parameters": [{"name": "content", "type": "string", "required": True}],
            }
        )
    )
    (tools_dir / "echo.json").write_text(
        json.dumps(
            {
                "name": "echo.shout",
                "description": "Echo a message back.",
                "parameters": [{"name": "message", "type": "string", "required": True}],
            }
        )
    )
    (tools_dir / "README.md").write_text("not a tool")

    registry = ToolRegistry()
    loaded = registry.load_from_directory(tools_dir)

    assert loaded == 2
    assert registry.has_tool(ToolName("note.create"))
    assert registry.has_tool(ToolName("echo.shout"))


def test_load_from_directory_rejects_external_metadata_in_local_files(tmp_path: Path) -> None:
    tools_dir = tmp_path / "tools"
    tools_dir.mkdir()
    (tools_dir / "rogue.yaml").write_text(
        yaml.safe_dump(
            {
                "name": "rogue.tool",
                "description": "Tries to masquerade as an MCP tool.",
                "parameters": [],
                "registration_source": "mcp",
                "registration_source_id": "evil",
                "upstream_tool_name": "rogue",
            }
        )
    )

    registry = ToolRegistry()

    with pytest.raises(ValueError, match="external registration metadata"):
        registry.load_from_directory(tools_dir)


def test_load_from_directory_enforces_schema_hash_when_provided(tmp_path: Path) -> None:
    tools_dir = tmp_path / "tools"
    tools_dir.mkdir()
    (tools_dir / "note.yaml").write_text(
        yaml.safe_dump(
            {
                "name": "note.create",
                "description": "Store a note.",
                "parameters": [{"name": "content", "type": "string", "required": True}],
                "schema_hash": "0" * 64,
            }
        )
    )

    registry = ToolRegistry()

    with pytest.raises(ValueError, match="schema hash mismatch"):
        registry.load_from_directory(tools_dir)


def test_load_from_directory_returns_zero_when_directory_missing(tmp_path: Path) -> None:
    registry = ToolRegistry()
    assert registry.load_from_directory(tmp_path / "nonexistent") == 0
