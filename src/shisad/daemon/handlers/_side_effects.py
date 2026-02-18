"""Shared side-effect classification helpers for handler flows."""

from __future__ import annotations

from shisad.core.tools.schema import ToolDefinition
from shisad.core.types import Capability

_SIDE_EFFECT_CAPABILITIES: frozenset[Capability] = frozenset(
    {
        Capability.EMAIL_WRITE,
        Capability.EMAIL_SEND,
        Capability.CALENDAR_WRITE,
        Capability.FILE_WRITE,
        Capability.HTTP_REQUEST,
        Capability.SHELL_EXEC,
        Capability.MESSAGE_SEND,
    }
)
_SIDE_EFFECT_TOOL_NAMES: frozenset[str] = frozenset({"report_anomaly"})


def is_side_effect_tool(tool: ToolDefinition) -> bool:
    if str(tool.name) in _SIDE_EFFECT_TOOL_NAMES:
        return True
    required = set(tool.capabilities_required)
    return bool(required & _SIDE_EFFECT_CAPABILITIES)
