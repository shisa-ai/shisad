"""Built-in shell execution tool definition for sandbox runtime."""

from __future__ import annotations

from shisad.core.tools.schema import ToolDefinition, ToolParameter
from shisad.core.types import Capability, ToolName


class ShellExecTool:
    """Schema-only shell tool executed via sandbox orchestrator."""

    @staticmethod
    def tool_definition() -> ToolDefinition:
        return ToolDefinition(
            name=ToolName("shell.exec"),
            description=(
                "Execute an explicit shell command via sandboxed executor runtime. "
                "Use only when the user asks to run a shell command or no structured "
                "runtime tool covers the task. Do not use for file discovery, "
                "directory listing, or file reads when fs.list or fs.read are available."
            ),
            parameters=[
                ToolParameter(
                    name="command",
                    type="array",
                    description=(
                        "Command argv tokens to execute. Each item must be one "
                        "executable or argument atom with no whitespace; do not "
                        "put an entire shell command in one item. Preserve the "
                        "requested executable and arguments; do not replace "
                        "Ledger-related commands with this example. For example, "
                        "the requested command `echo Hello Ledger!` should be "
                        '["echo", "Hello", "Ledger!"].'
                    ),
                    required=True,
                    items_type="string",
                    items_semantic_type="command_token",
                ),
                ToolParameter(
                    name="command_intent",
                    type="string",
                    description=(
                        "Planner-owned intent marker. Set to 'execute' only when "
                        "calling shell.exec to run the command; for informational "
                        "mentions or explanations, do not call shell.exec."
                    ),
                    required=True,
                    enum=["execute", "informational"],
                ),
                ToolParameter(
                    name="read_paths",
                    type="array",
                    description="Read-only filesystem paths required by command",
                    required=False,
                    items_type="string",
                    items_semantic_type="workspace_path",
                ),
                ToolParameter(
                    name="write_paths",
                    type="array",
                    description="Writable filesystem paths required by command",
                    required=False,
                    items_type="string",
                    items_semantic_type="workspace_path",
                ),
                ToolParameter(
                    name="network_urls",
                    type="array",
                    description="Network destinations requested by command",
                    required=False,
                    items_type="string",
                    items_semantic_type="url",
                ),
                ToolParameter(
                    name="env",
                    type="object",
                    description="Environment variables requested for command execution",
                    required=False,
                ),
                ToolParameter(
                    name="cwd",
                    type="string",
                    description="Working directory for command execution",
                    required=False,
                    semantic_type="workspace_path",
                ),
            ],
            capabilities_required=[Capability.SHELL_EXEC],
            sandbox_type="nsjail",
            require_confirmation=False,
        )
