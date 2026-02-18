"""Unit checks for shared handler side-effect classification."""

from __future__ import annotations

from shisad.core.tools.schema import ToolDefinition, ToolParameter
from shisad.core.types import Capability, ToolName
from shisad.daemon.handlers._side_effects import is_side_effect_tool


def _tool(
    *,
    name: str,
    capabilities: list[Capability],
) -> ToolDefinition:
    return ToolDefinition(
        name=ToolName(name),
        description=name,
        parameters=[ToolParameter(name="arg", type="string", required=False)],
        capabilities_required=capabilities,
    )


def test_m7_side_effect_classifier_marks_high_impact_capability_tools() -> None:
    tool = _tool(name="shell_exec", capabilities=[Capability.SHELL_EXEC])
    assert is_side_effect_tool(tool) is True


def test_m7_side_effect_classifier_marks_named_alarm_tool() -> None:
    tool = _tool(name="report_anomaly", capabilities=[])
    assert is_side_effect_tool(tool) is True


def test_m7_side_effect_classifier_excludes_read_only_tools() -> None:
    tool = _tool(name="fs.read", capabilities=[Capability.FILE_READ])
    assert is_side_effect_tool(tool) is False
