"""F4B end-user containment and dynamic-skill provenance journeys."""

from __future__ import annotations

import asyncio
from contextlib import suppress
from pathlib import Path

import pytest
import yaml

from shisad.core.api.transport import ControlClient
from shisad.core.config import DaemonConfig
from shisad.daemon.runner import run_daemon
from tests.helpers.daemon import wait_for_socket


def _write_command_skill(path: Path) -> None:
    path.mkdir(parents=True)
    manifest = {
        "manifest_version": "1.0.0",
        "name": "f4-command",
        "version": "1.0.0",
        "author": "fixture",
        "signature": "",
        "source_repo": "https://example.test/f4-command",
        "description": "F4 command journey",
        "capabilities": {
            "network": [],
            "filesystem": [],
            "shell": [{"command": "echo", "reason": "journey output"}],
            "environment": [],
        },
        "dependencies": [],
        "tools": [
            {
                "name": "run",
                "description": "Run the declared command.",
                "parameters": [
                    {
                        "name": "command",
                        "type": "array",
                        "items_type": "string",
                        "required": True,
                    }
                ],
                "destinations": [],
                "require_confirmation": False,
            }
        ],
    }
    (path / "skill.manifest.yaml").write_text(
        yaml.safe_dump(manifest, sort_keys=False), encoding="utf-8"
    )
    (path / "SKILL.md").write_text("F4 command skill.\n", encoding="utf-8")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("profile", "allowed", "actual_backend"),
    [
        ("supported", False, None),
        ("expert_host_fallback", True, "host"),
    ],
)
async def test_f4_dynamic_skill_preserves_declared_use_without_silent_host_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    profile: str,
    allowed: bool,
    actual_backend: str | None,
) -> None:
    monkeypatch.setenv("SHISAD_MODEL_BASE_URL", "https://api.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_PLANNER_BASE_URL", "https://planner.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_EMBEDDINGS_BASE_URL", "https://embed.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_MONITOR_BASE_URL", "https://monitor.example.com/v1")
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        yaml.safe_dump(
            {
                "skills": {"require_signature_for_auto_install": False},
                "sandbox": {"containment_profile": profile},
                "default_require_confirmation": profile == "expert_host_fallback",
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=policy_path,
    )
    skill_path = tmp_path / "skill"
    _write_command_skill(skill_path)
    daemon_task = asyncio.create_task(run_daemon(config))
    client = ControlClient(config.socket_path)
    await wait_for_socket(config.socket_path)
    await client.connect()
    try:
        installed = await client.call(
            "skill.install", {"skill_path": str(skill_path), "approve_untrusted": True}
        )
        assert installed["status"] == "installed"
        doctor = await client.call("doctor.check", {"component": "sandbox"})
        sandbox_status = doctor["checks"]["sandbox"]
        assert sandbox_status["sandbox_policy"]["containment_profile"] == profile
        assert sandbox_status["backends"]["nsjail"]["available"] is False
        assert "default_backend_unavailable:nsjail" in sandbox_status["problems"]
        assert ("expert_host_fallback_enabled" in sandbox_status["problems"]) is (
            profile == "expert_host_fallback"
        )
        session = await client.call(
            "session.create",
            {"channel": "cli", "user_id": "alice", "workspace_id": "ws1"},
        )
        result = await client.call(
            "tool.execute",
            {
                "session_id": session["session_id"],
                "tool_name": "skill.f4-command.run",
                "command": ["echo", "declared-f4-output"],
            },
        )

        if profile == "expert_host_fallback":
            assert result["confirmation_required"] is True
            assert any("Expert host fallback enabled" in warning for warning in result["warnings"])
            confirmed = await client.call(
                "action.confirm",
                {
                    "confirmation_id": result["confirmation_id"],
                    "decision_nonce": result["decision_nonce"],
                    "reason": "explicit expert fallback journey",
                },
            )
            assert confirmed["confirmed"] is True
            degraded = await client.call(
                "audit.query",
                {
                    "event_type": "SandboxDegraded",
                    "session_id": session["session_id"],
                    "limit": 20,
                },
            )
            fallback_events = [
                event["data"]
                for event in degraded["events"]
                if "expert_host_fallback" in event["data"].get("controls", [])
            ]
            assert fallback_events
            assert fallback_events[-1]["backend"] == "nsjail"
            return

        assert result["allowed"] is allowed, (
            result["reason"],
            result["degraded_controls"],
            result["containment_profile"],
        )
        assert result["containment_profile"] == profile
        assert result["degraded_mode"] == ("fail_closed" if profile == "supported" else "fail_open")
        assert result["requested_backend"] == "nsjail"
        assert result["actual_backend"] == actual_backend
        assert result["host_fallback_used"] is (profile == "expert_host_fallback")
        if allowed:
            assert "declared-f4-output" in result["stdout"]
        else:
            assert "requested sandbox backend" in result["next_action"]
            assert result["reason"] in {
                "degraded_enforcement",
                "runtime_isolation_unavailable",
            }
    finally:
        with suppress(Exception):
            await client.call("daemon.shutdown")
        await client.close()
        await asyncio.wait_for(daemon_task, timeout=3)
