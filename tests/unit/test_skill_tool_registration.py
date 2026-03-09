"""M1 skill ToolRegistry bridge coverage."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from shisad.core.tools.registry import ToolRegistry
from shisad.core.types import Capability, ToolName
from shisad.security.policy import SkillPolicy
from shisad.skills.manager import SkillManager
from shisad.skills.manifest import parse_manifest


def _manifest_payload(
    *,
    name: str = "calendar-helper",
    version: str = "1.0.0",
    tools: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "manifest_version": "1.0.0",
        "name": name,
        "version": version,
        "author": "trusted-dev",
        "signature": "",
        "source_repo": "https://github.com/trusted-dev/calendar-helper",
        "description": "calendar helper",
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
