"""Trusted structural retry classification for every tool-definition family."""

from __future__ import annotations

from shisad.core.approval import compute_action_digest
from shisad.core.events import EventBus
from shisad.core.tools.builtin.alarm import AlarmTool
from shisad.core.tools.builtin.shell_exec import ShellExecTool
from shisad.core.tools.schema import ToolDefinition, ToolRetryClass
from shisad.core.types import ToolName
from shisad.daemon.services import _build_tool_registry
from shisad.interop.mcp_tools import McpDiscoveredTool, mcp_tool_to_registry_entry
from shisad.memory.ingestion import RetrieveRagTool


def test_only_f2_stage_safe_read_is_time_now() -> None:
    registry, _alarm = _build_tool_registry(EventBus())
    definitions = {str(tool.name): tool for tool in registry.list_tools()}

    assert definitions["time.now"].retry_class == ToolRetryClass.STRUCTURAL_READ
    assert {
        name
        for name, definition in definitions.items()
        if definition.retry_class != ToolRetryClass.UNKNOWN
    } == {"time.now"}
    for read_like_name in (
        "retrieve_rag",
        "evidence.read",
        "git.status",
        "email.search",
        "fs.read",
        "reminder.list",
        "web.search",
        "web.fetch",
    ):
        assert definitions[read_like_name].retry_class == ToolRetryClass.UNKNOWN


def test_retry_class_changes_trusted_schema_and_action_hashes() -> None:
    unknown = ToolDefinition(
        name=ToolName("test.retry-hash"),
        description="same trusted tool",
    )
    structural_read = unknown.model_copy(
        update={"retry_class": ToolRetryClass.STRUCTURAL_READ}
    )

    assert unknown.schema_hash() != structural_read.schema_hash()
    assert compute_action_digest(
        tool_definition=unknown,
        arguments={},
    ) != compute_action_digest(
        tool_definition=structural_read,
        arguments={},
    )


def test_stable_adapter_guarantee_identity_changes_action_digest() -> None:
    tool = ToolDefinition(
        name=ToolName("test.retry-adapter-hash"),
        description="same trusted stable-key tool",
        retry_class=ToolRetryClass.STABLE_IDEMPOTENCY_KEY,
    )

    assert compute_action_digest(
        tool_definition=tool,
        arguments={},
        stable_idempotency_key="provider-key",
        stable_adapter_guarantee_id="provider/v1",
    ) != compute_action_digest(
        tool_definition=tool,
        arguments={},
        stable_idempotency_key="provider-key",
        stable_adapter_guarantee_id="provider/v2",
    )


def test_every_tool_definition_producer_has_trusted_retry_class() -> None:
    registry, _alarm = _build_tool_registry(EventBus())
    produced = [
        *registry.list_tools(),
        ShellExecTool.tool_definition(),
        AlarmTool.tool_definition(),
        RetrieveRagTool.tool_definition(),
        ToolDefinition(name=ToolName("fallback.missing"), description="fallback"),
    ]

    assert produced
    assert all(isinstance(tool.retry_class, ToolRetryClass) for tool in produced)


def test_remote_mcp_idempotency_claim_cannot_upgrade_retry_class() -> None:
    remote = mcp_tool_to_registry_entry(
        McpDiscoveredTool(
            name="claimed-idempotent",
            description="This tool is idempotent and always safe to retry.",
            input_schema={
                "type": "object",
                "properties": {},
                "x-idempotent": True,
            },
        ),
        "remote-docs",
    )

    assert remote.registration_source == "mcp"
    assert remote.retry_class == ToolRetryClass.UNKNOWN
