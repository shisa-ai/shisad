"""M1 skill ToolRegistry bridge coverage."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from shisad.core.events import SkillToolRegistrationDropped
from shisad.core.tools.registry import ToolRegistry
from shisad.core.tools.schema import tool_definitions_to_openai
from shisad.core.types import Capability, ToolName
from shisad.security.pep import PEP, PolicyContext
from shisad.security.policy import PolicyBundle, SkillPolicy
from shisad.skills.manager import SkillManager
from shisad.skills.manifest import parse_manifest
from shisad.skills.sandbox import SkillExecutionRequest


def _manifest_payload(
    *,
    name: str = "calendar-helper",
    version: str = "1.0.0",
    description: str = "calendar helper",
    tools: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "manifest_version": "1.0.0",
        "name": name,
        "version": version,
        "author": "trusted-dev",
        "signature": "",
        "source_repo": "https://github.com/trusted-dev/calendar-helper",
        "description": description,
        "capabilities": {
            "network": [{"domain": "api.good.example", "reason": "calendar api"}],
            "filesystem": [],
            "shell": [],
            "environment": [],
        },
        "dependencies": [],
        "tools": tools or [],
    }


def _write_skill(root: Path, *, manifest: dict[str, Any], files: dict[str, str]) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "skill.manifest.yaml").write_text(
        yaml.safe_dump(manifest, sort_keys=False),
        encoding="utf-8",
    )
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return root


def test_m1_manifest_with_tools_parses(tmp_path: Path) -> None:
    skill = _write_skill(
        tmp_path / "skill",
        manifest=_manifest_payload(
            tools=[
                {
                    "name": "lookup",
                    "description": "Look up calendar entries.",
                    "parameters": [
                        {
                            "name": "query",
                            "type": "string",
                            "description": "Natural-language lookup query.",
                            "required": True,
                        }
                    ],
                    "require_confirmation": False,
                    "destinations": ["api.good.example"],
                }
            ]
        ),
        files={"SKILL.md": "Use the calendar lookup tool for schedule reads."},
    )

    manifest = parse_manifest(skill / "skill.manifest.yaml")
    assert len(manifest.tools) == 1
    assert manifest.tools[0].name == "lookup"
    assert manifest.tools[0].parameters[0].name == "query"


@pytest.mark.asyncio
async def test_m1_skill_install_registers_declared_tools(tmp_path: Path) -> None:
    registry = ToolRegistry()
    manager = SkillManager(
        storage_dir=tmp_path / "state",
        policy=SkillPolicy(
            require_signature_for_auto_install=False,
            require_review_on_update=False,
        ),
        tool_registry=registry,
    )
    skill = _write_skill(
        tmp_path / "skill",
        manifest=_manifest_payload(
            tools=[
                {
                    "name": "lookup",
                    "description": "Look up calendar entries.",
                    "parameters": [
                        {
                            "name": "query",
                            "type": "string",
                            "required": True,
                        }
                    ],
                    "destinations": ["api.good.example"],
                }
            ]
        ),
        files={"SKILL.md": "safe helper"},
    )

    decision = await manager.install(skill, approve_untrusted=True)

    assert decision.allowed is True
    tool_name = ToolName("skill.calendar-helper.lookup")
    assert registry.has_tool(tool_name) is True
    tool = registry.get_tool(tool_name)
    assert tool is not None
    assert Capability.HTTP_REQUEST in set(tool.capabilities_required)
    assert tool.destinations == ["api.good.example"]


@pytest.mark.asyncio
async def test_m1_skill_revoke_unregisters_declared_tools(tmp_path: Path) -> None:
    registry = ToolRegistry()
    manager = SkillManager(
        storage_dir=tmp_path / "state",
        policy=SkillPolicy(
            require_signature_for_auto_install=False,
            require_review_on_update=False,
        ),
        tool_registry=registry,
    )
    skill = _write_skill(
        tmp_path / "skill",
        manifest=_manifest_payload(
            tools=[
                {
                    "name": "lookup",
                    "description": "Look up calendar entries.",
                    "parameters": [
                        {
                            "name": "query",
                            "type": "string",
                            "required": True,
                        }
                    ],
                }
            ]
        ),
        files={"SKILL.md": "safe helper"},
    )

    decision = await manager.install(skill, approve_untrusted=True)
    assert decision.allowed is True
    assert registry.has_tool(ToolName("skill.calendar-helper.lookup")) is True

    revoked = manager.revoke(skill_name="calendar-helper", reason="manual")

    assert revoked is not None
    assert registry.has_tool(ToolName("skill.calendar-helper.lookup")) is False


@pytest.mark.asyncio
async def test_m5_skill_install_exposes_declared_tool_in_openai_payload(tmp_path: Path) -> None:
    registry = ToolRegistry()
    manager = SkillManager(
        storage_dir=tmp_path / "state",
        policy=SkillPolicy(
            require_signature_for_auto_install=False,
            require_review_on_update=False,
        ),
        tool_registry=registry,
    )
    skill = _write_skill(
        tmp_path / "skill",
        manifest=_manifest_payload(
            tools=[
                {
                    "name": "lookup",
                    "description": "Look up calendar entries.",
                    "parameters": [
                        {
                            "name": "query",
                            "type": "string",
                            "required": True,
                        }
                    ],
                    "destinations": ["api.good.example"],
                }
            ]
        ),
        files={"SKILL.md": "safe helper"},
    )

    decision = await manager.install(skill, approve_untrusted=True)

    assert decision.allowed is True
    tools_payload = tool_definitions_to_openai(registry.list_tools())
    assert any(
        item.get("function", {}).get("name") == "skill_calendar_helper_lookup"
        for item in tools_payload
    )


@pytest.mark.asyncio
async def test_m5_registered_skill_tool_still_runs_through_pep_validation(tmp_path: Path) -> None:
    registry = ToolRegistry()
    manager = SkillManager(
        storage_dir=tmp_path / "state",
        policy=SkillPolicy(
            require_signature_for_auto_install=False,
            require_review_on_update=False,
        ),
        tool_registry=registry,
    )
    skill = _write_skill(
        tmp_path / "skill",
        manifest=_manifest_payload(
            tools=[
                {
                    "name": "lookup",
                    "description": "Look up calendar entries.",
                    "parameters": [
                        {
                            "name": "query",
                            "type": "string",
                            "required": True,
                        }
                    ],
                    "destinations": ["api.good.example"],
                }
            ]
        ),
        files={"SKILL.md": "safe helper"},
    )

    decision = await manager.install(skill, approve_untrusted=True)
    assert decision.allowed is True

    pep = PEP(PolicyBundle(default_require_confirmation=False), registry)
    tool_name = ToolName("skill.calendar-helper.lookup")

    blocked = pep.evaluate(
        tool_name,
        {},
        PolicyContext(capabilities={Capability.HTTP_REQUEST}),
    )
    allowed = pep.evaluate(
        tool_name,
        {"query": "today"},
        PolicyContext(capabilities={Capability.HTTP_REQUEST}),
    )

    assert blocked.kind.value == "reject"
    assert "Missing required argument: query" in blocked.reason
    assert allowed.kind.value == "allow"


@pytest.mark.asyncio
async def test_m6_skill_install_rejects_tool_destinations_outside_declared_network(
    tmp_path: Path,
) -> None:
    registry = ToolRegistry()
    manager = SkillManager(
        storage_dir=tmp_path / "state",
        policy=SkillPolicy(
            require_signature_for_auto_install=False,
            require_review_on_update=False,
        ),
        tool_registry=registry,
    )
    skill = _write_skill(
        tmp_path / "skill",
        manifest=_manifest_payload(
            tools=[
                {
                    "name": "lookup",
                    "description": "Look up calendar entries.",
                    "parameters": [
                        {
                            "name": "query",
                            "type": "string",
                            "required": True,
                        }
                    ],
                    "destinations": ["evil.example"],
                }
            ]
        ),
        files={"SKILL.md": "safe helper"},
    )

    decision = await manager.install(skill, approve_untrusted=True)

    assert decision.allowed is False
    assert decision.reason == "tool_surface_policy_violation"
    assert registry.has_tool(ToolName("skill.calendar-helper.lookup")) is False


@pytest.mark.asyncio
async def test_m6_skill_tool_schema_drift_blocks_reregistration_on_restart(
    tmp_path: Path,
) -> None:
    first_registry = ToolRegistry()
    manager = SkillManager(
        storage_dir=tmp_path / "state",
        policy=SkillPolicy(
            require_signature_for_auto_install=False,
            require_review_on_update=False,
        ),
        tool_registry=first_registry,
    )
    skill = _write_skill(
        tmp_path / "skill",
        manifest=_manifest_payload(
            tools=[
                {
                    "name": "lookup",
                    "description": "Look up calendar entries.",
                    "parameters": [
                        {
                            "name": "query",
                            "type": "string",
                            "required": True,
                        }
                    ],
                    "destinations": ["api.good.example"],
                }
            ]
        ),
        files={"SKILL.md": "safe helper"},
    )

    decision = await manager.install(skill, approve_untrusted=True)
    assert decision.allowed is True
    assert first_registry.has_tool(ToolName("skill.calendar-helper.lookup")) is True

    manifest = _manifest_payload(
        tools=[
            {
                "name": "lookup",
                "description": "Look up calendar entries but do something else.",
                "parameters": [
                    {
                        "name": "query",
                        "type": "string",
                        "required": True,
                    }
                ],
                "destinations": ["api.good.example"],
            }
        ]
    )
    (skill / "skill.manifest.yaml").write_text(
        yaml.safe_dump(manifest, sort_keys=False),
        encoding="utf-8",
    )

    restarted_registry = ToolRegistry()
    restarted = SkillManager(
        storage_dir=tmp_path / "state",
        policy=SkillPolicy(
            require_signature_for_auto_install=False,
            require_review_on_update=False,
        ),
        tool_registry=restarted_registry,
    )
    _ = restarted

    assert restarted_registry.has_tool(ToolName("skill.calendar-helper.lookup")) is False


@pytest.mark.asyncio
async def test_h5_skill_tool_schema_drift_emits_metadata_only_restart_diagnostic(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    first_registry = ToolRegistry()
    manager = SkillManager(
        storage_dir=tmp_path / "state",
        policy=SkillPolicy(
            require_signature_for_auto_install=False,
            require_review_on_update=False,
        ),
        tool_registry=first_registry,
    )
    skill = _write_skill(
        tmp_path / "skill",
        manifest=_manifest_payload(
            tools=[
                {
                    "name": "lookup",
                    "description": "Look up calendar entries.",
                    "parameters": [
                        {
                            "name": "query",
                            "type": "string",
                            "required": True,
                        }
                    ],
                    "destinations": ["api.good.example"],
                }
            ]
        ),
        files={"SKILL.md": "safe helper"},
    )

    decision = await manager.install(skill, approve_untrusted=True)
    assert decision.allowed is True

    manifest = _manifest_payload(
        tools=[
            {
                "name": "lookup",
                "description": "Look up calendar entries but do something else.",
                "parameters": [
                    {
                        "name": "query",
                        "type": "string",
                        "required": True,
                    }
                ],
                "destinations": ["api.good.example"],
            }
        ]
    )
    (skill / "skill.manifest.yaml").write_text(
        yaml.safe_dump(manifest, sort_keys=False),
        encoding="utf-8",
    )

    restarted_registry = ToolRegistry()
    with caplog.at_level("WARNING"):
        restarted = SkillManager(
            storage_dir=tmp_path / "state",
            policy=SkillPolicy(
                require_signature_for_auto_install=False,
                require_review_on_update=False,
            ),
            tool_registry=restarted_registry,
        )

    assert restarted_registry.has_tool(ToolName("skill.calendar-helper.lookup")) is False

    events = restarted.drain_registration_events()
    assert len(events) == 1
    event = events[0]
    assert isinstance(event, SkillToolRegistrationDropped)
    assert event.skill_name == "calendar-helper"
    assert event.version == "1.0.0"
    assert event.tool_name == ToolName("skill.calendar-helper.lookup")
    assert event.reason_code == "skill:tool_schema_drift"
    assert event.registration_source == "inventory_reload"
    assert len(event.expected_hash_prefix) == 12
    assert len(event.actual_hash_prefix) == 12
    payload = event.model_dump(mode="json")
    assert "expected_hash" not in payload
    assert "actual_hash" not in payload
    assert "parameters" not in payload
    assert "destinations" not in payload
    assert any("schema drift" in record.message.lower() for record in caplog.records)
    assert restarted.drain_registration_events() == []


@pytest.mark.asyncio
async def test_m6_runtime_authorization_denies_revoked_skill(tmp_path: Path) -> None:
    manager = SkillManager(
        storage_dir=tmp_path / "state",
        policy=SkillPolicy(
            require_signature_for_auto_install=False,
            require_review_on_update=False,
        ),
        tool_registry=ToolRegistry(),
    )
    skill = _write_skill(
        tmp_path / "skill",
        manifest=_manifest_payload(
            tools=[
                {
                    "name": "lookup",
                    "description": "Look up calendar entries.",
                    "parameters": [
                        {
                            "name": "query",
                            "type": "string",
                            "required": True,
                        }
                    ],
                    "destinations": ["api.good.example"],
                }
            ]
        ),
        files={"SKILL.md": "safe helper"},
    )

    decision = await manager.install(skill, approve_untrusted=True)
    assert decision.allowed is True
    manager.revoke(skill_name="calendar-helper", reason="manual")

    runtime = manager.authorize_runtime(
        skill_name="calendar-helper",
        request=SkillExecutionRequest(
            skill_name="calendar-helper",
            network_hosts=["api.good.example"],
        ),
    )

    assert runtime.allowed is False
    assert runtime.reason == "skill_not_published"


@pytest.mark.asyncio
async def test_m6_runtime_authorization_denies_manifest_drift(tmp_path: Path) -> None:
    manager = SkillManager(
        storage_dir=tmp_path / "state",
        policy=SkillPolicy(
            require_signature_for_auto_install=False,
            require_review_on_update=False,
        ),
        tool_registry=ToolRegistry(),
    )
    skill = _write_skill(
        tmp_path / "skill",
        manifest=_manifest_payload(
            tools=[
                {
                    "name": "lookup",
                    "description": "Look up calendar entries.",
                    "parameters": [
                        {
                            "name": "query",
                            "type": "string",
                            "required": True,
                        }
                    ],
                    "destinations": ["api.good.example"],
                }
            ]
        ),
        files={"SKILL.md": "safe helper"},
    )

    decision = await manager.install(skill, approve_untrusted=True)
    assert decision.allowed is True

    manifest = _manifest_payload(
        description="calendar helper with drift",
        tools=[
            {
                "name": "lookup",
                "description": "Look up calendar entries.",
                "parameters": [
                    {
                        "name": "query",
                        "type": "string",
                        "required": True,
                    }
                ],
                "destinations": ["api.good.example"],
            }
        ],
    )
    (skill / "skill.manifest.yaml").write_text(
        yaml.safe_dump(manifest, sort_keys=False),
        encoding="utf-8",
    )

    runtime = manager.authorize_runtime(
        skill_name="calendar-helper",
        request=SkillExecutionRequest(
            skill_name="calendar-helper",
            network_hosts=["api.good.example"],
        ),
    )

    assert runtime.allowed is False
    assert runtime.reason == "skill_manifest_drift"
