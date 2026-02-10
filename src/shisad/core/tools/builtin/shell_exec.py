"""Built-in shell execution tool definition for sandbox runtime."""

from __future__ import annotations

from shisad.core.tools.schema import ToolDefinition, ToolParameter
from shisad.core.types import Capability, ToolName


class ShellExecTool:
    """Schema-only shell tool executed via sandbox orchestrator."""

    @staticmethod
    def tool_definition() -> ToolDefinition:
        return ToolDefinition(
            name=ToolName("shell_exec"),
            description="Execute a shell command via sandboxed executor runtime.",
            parameters=[
                ToolParameter(
                    name="command",
                    type="array",
                    description="Command token list to execute",
                    required=True,
                ),
                ToolParameter(
                    name="read_paths",
                    type="array",
                    description="Read-only filesystem paths required by command",
                    required=False,
                ),
                ToolParameter(
                    name="write_paths",
                    type="array",
                    description="Writable filesystem paths required by command",
                    required=False,
                ),
                ToolParameter(
                    name="network_urls",
                    type="array",
                    description="Network destinations requested by command",
                    required=False,
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
                ),
            ],
            capabilities_required=[Capability.SHELL_EXEC],
            sandbox_type="nsjail",
            require_confirmation=False,
        )
