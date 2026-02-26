"""Unit checks for conformance harness helpers."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

from shisad.core.tools.registry import ToolRegistry
from shisad.core.tools.schema import ToolDefinition, ToolParameter
from shisad.core.types import Capability, ToolName


def _load_conformance_module():
    script_path = Path(__file__).resolve().parents[2] / "scripts" / "conformance_harness.py"
    spec = importlib.util.spec_from_file_location("conformance_harness", script_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_conformance_load_cases_fails_fast_on_invalid_case(tmp_path: Path) -> None:
    conformance_harness = _load_conformance_module()
    fixture_path = tmp_path / "cases.json"
    fixture_path.write_text(
        json.dumps(
            {
                "version": "1",
                "cases": [
                    {
                        "id": "missing_prompt",
                        "available_tools": ["web.search"],
                        "expected_behavior": "tool_call",
                        "expected_tools": ["web.search"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="invalid 'prompt'"):
        conformance_harness._load_cases(fixture_path)


def test_conformance_load_cases_rejects_expected_tools_not_in_allowlist(
    tmp_path: Path,
) -> None:
    conformance_harness = _load_conformance_module()
    fixture_path = tmp_path / "cases.json"
    fixture_path.write_text(
        json.dumps(
            {
                "version": "1",
                "cases": [
                    {
                        "id": "bad_expected_tool",
                        "prompt": "test",
                        "available_tools": ["web.search"],
                        "expected_behavior": "tool_call",
                        "expected_tools": ["fs.read"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="expected_tools not in available_tools"):
        conformance_harness._load_cases(fixture_path)


def test_conformance_validate_action_schema_checks_types_and_extra_arguments() -> None:
    conformance_harness = _load_conformance_module()
    registry = ToolRegistry()
    registry.register(
        ToolDefinition(
            name=ToolName("web.search"),
            description="Search",
            parameters=[
                ToolParameter(name="query", type="string", required=True),
                ToolParameter(name="limit", type="integer", required=False),
            ],
            capabilities_required=[Capability.HTTP_REQUEST],
        )
    )
    action = conformance_harness.ActionProposal.model_validate(
        {
            "action_id": "a1",
            "tool_name": "web.search",
            "arguments": {"query": 123, "unexpected": "x"},
            "reasoning": "test",
            "data_sources": [],
        }
    )

    errors = conformance_harness._validate_action_schema(
        actions=[action],
        planner_label="native",
        tool_registry=registry,
        case_allowed_tools={"web.search"},
    )

    assert any("expected type 'string'" in error for error in errors)
    assert any("Unexpected argument" in error for error in errors)


def test_conformance_case_expectation_fails_on_unexpected_extra_tools() -> None:
    conformance_harness = _load_conformance_module()
    case = conformance_harness.ConformanceCase(
        case_id="strict",
        prompt="test",
        available_tools=["web.search", "fs.read"],
        expected_behavior="tool_call",
        expected_tools=["web.search"],
        send_tools_payload=True,
        expect_content_extraction=False,
    )

    passed, errors = conformance_harness._case_expectation_passed(
        case=case,
        observed_behavior="tool_call",
        observed_tools={"web.search", "fs.read"},
        content_actions=[],
    )
    assert passed is False
    assert any(error.startswith("unexpected_tools:") for error in errors)


def test_conformance_case_expectation_allows_extra_tools_when_configured() -> None:
    conformance_harness = _load_conformance_module()
    case = conformance_harness.ConformanceCase(
        case_id="allow-extras",
        prompt="test",
        available_tools=["web.search", "fs.read"],
        expected_behavior="tool_call",
        expected_tools=["web.search"],
        send_tools_payload=True,
        expect_content_extraction=False,
        allow_extra_tools=True,
    )

    passed, errors = conformance_harness._case_expectation_passed(
        case=case,
        observed_behavior="tool_call",
        observed_tools={"web.search", "fs.read"},
        content_actions=[],
    )
    assert passed is True
    assert errors == []
