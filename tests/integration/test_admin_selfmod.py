"""M1 integration coverage for admin self-modification and hot-reload."""

from __future__ import annotations

import asyncio
import json
import subprocess
from contextlib import suppress
from pathlib import Path
from typing import Any

import pytest
import yaml

from shisad.core.api.transport import ControlClient
from shisad.core.config import DaemonConfig
from shisad.core.planner import Planner, PlannerOutput, PlannerResult
from shisad.daemon.runner import run_daemon


async def _wait_for_socket(path: Path, timeout: float = 5.0) -> None:
    end = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < end:
        if path.exists():
            return
        await asyncio.sleep(0.01)
    raise TimeoutError(f"Timed out waiting for socket {path}")


@pytest.fixture
def model_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SHISAD_MODEL_BASE_URL", "https://api.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_PLANNER_BASE_URL", "https://planner.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_EMBEDDINGS_BASE_URL", "https://embed.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_MONITOR_BASE_URL", "https://monitor.example.com/v1")


def _generate_ssh_keypair(tmp_path: Path, *, name: str) -> Path:
    key_path = tmp_path / name
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key_path)],
        check=True,
        capture_output=True,
        text=True,
    )
    return key_path


def _write_allowed_signers(path: Path, *, principal: str, public_key: Path) -> None:
    key_type, key_value, *_rest = public_key.read_text(encoding="utf-8").strip().split()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        f'{principal} namespaces="file" {key_type} {key_value}\n',
        encoding="utf-8",
    )


def _sign_manifest(manifest_path: Path, *, key_path: Path) -> None:
    subprocess.run(
        ["ssh-keygen", "-Y", "sign", "-f", str(key_path), "-n", "file", str(manifest_path)],
        check=True,
        capture_output=True,
        text=True,
    )


def _write_signed_skill_bundle(root: Path, *, key_path: Path, version: str = "1.0.0") -> Path:
    payload_root = root / "payload"
    payload_root.mkdir(parents=True, exist_ok=True)
    (payload_root / "skill.manifest.yaml").write_text(
        yaml.safe_dump(
            {
                "manifest_version": "1.0.0",
                "name": "calendar-helper",
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
                "tools": [
                    {
                        "name": "lookup",
                        "description": "Look up calendar entries.",
                        "parameters": [{"name": "query", "type": "string", "required": True}],
                        "destinations": ["api.good.example"],
                    }
                ],
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    (payload_root / "SKILL.md").write_text("Use the lookup tool for schedule reads.\n")
    files: list[dict[str, Any]] = []
    for path in sorted(payload_root.rglob("*")):
        if not path.is_file():
            continue
        data = path.read_bytes()
        files.append(
            {
                "path": str(path.relative_to(root)),
                "sha256": __import__("hashlib").sha256(data).hexdigest(),
                "size": len(data),
            }
        )
    manifest = {
        "schema_version": "1",
        "type": "skill_bundle",
        "name": "calendar-helper",
        "version": version,
        "created_at": "2026-03-09T00:00:00+00:00",
        "files": files,
        "declared_capabilities": {
            "network": ["api.good.example"],
            "filesystem": [],
            "shell": [],
            "environment": [],
            "tools": ["skill.calendar-helper.lookup"],
        },
        "provenance": {
            "source_repo": "https://github.com/trusted-dev/calendar-helper",
            "builder_id": "pytest",
        },
    }
    manifest_path = root / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    _sign_manifest(manifest_path, key_path=key_path)
    return root


async def _start_daemon(
    tmp_path: Path,
    *,
    allowed_signers_path: Path,
) -> tuple[asyncio.Task[None], ControlClient]:
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
        log_level="INFO",
        selfmod_allowed_signers_path=allowed_signers_path,
    )
    daemon_task = asyncio.create_task(run_daemon(config))
    client = ControlClient(config.socket_path)
    await _wait_for_socket(config.socket_path)
    await client.connect()
    return daemon_task, client


async def _shutdown(daemon_task: asyncio.Task[None], client: ControlClient) -> None:
    with suppress(Exception):
        await client.call("daemon.shutdown")
    await client.close()
    await asyncio.wait_for(daemon_task, timeout=3)


@pytest.mark.asyncio
async def test_m1_admin_selfmod_skill_apply_hot_reloads_tools_without_restart(
    model_env: None,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured_tools: list[list[dict[str, Any]]] = []

    async def _capture_propose(
        self: Planner,
        user_content: str,
        context: object,
        *,
        tools: list[dict[str, Any]] | None = None,
        persona_tone_override: str | None = None,
    ) -> PlannerResult:
        _ = (self, user_content, context, persona_tone_override)
        captured_tools.append(list(tools or []))
        return PlannerResult(
            output=PlannerOutput(assistant_response="ok", actions=[]),
            evaluated=[],
            attempts=1,
            provider_response=None,
            messages_sent=(),
        )

    monkeypatch.setattr(Planner, "propose", _capture_propose)

    key_path = _generate_ssh_keypair(tmp_path, name="dev-key")
    allowed_signers = tmp_path / "allowed_signers"
    _write_allowed_signers(
        allowed_signers,
        principal="dev",
        public_key=Path(f"{key_path}.pub"),
    )
    artifact = _write_signed_skill_bundle(tmp_path / "skill-bundle", key_path=key_path)

    daemon_task, client = await _start_daemon(
        tmp_path,
        allowed_signers_path=allowed_signers,
    )
    try:
        proposal = await client.call(
            "admin.selfmod.propose",
            {"artifact_path": str(artifact)},
        )
        assert proposal["valid"] is True
        assert proposal["artifact_type"] == "skill_bundle"

        preview = await client.call(
            "admin.selfmod.apply",
            {"proposal_id": proposal["proposal_id"]},
        )
        assert preview["applied"] is False
        assert preview["requires_confirmation"] is True

        applied = await client.call(
            "admin.selfmod.apply",
            {"proposal_id": proposal["proposal_id"], "confirm": True},
        )
        assert applied["applied"] is True
        change_id = str(applied["change_id"])
        assert change_id

        status = await client.call("daemon.status")
        assert "skill.calendar-helper.lookup" in status["tools_registered"]

        created = await client.call("session.create", {"channel": "cli"})
        await client.call(
            "session.message",
            {"session_id": created["session_id"], "content": "hello"},
        )
        assert captured_tools
        assert any(
            item.get("function", {}).get("name") == "skill_calendar_helper_lookup"
            for item in captured_tools[-1]
        )

        rollback = await client.call(
            "admin.selfmod.rollback",
            {"change_id": change_id},
        )
        assert rollback["rolled_back"] is True

        status = await client.call("daemon.status")
        assert "skill.calendar-helper.lookup" not in status["tools_registered"]

        await client.call(
            "session.message",
            {"session_id": created["session_id"], "content": "hello again"},
        )
        assert not any(
            item.get("function", {}).get("name") == "skill_calendar_helper_lookup"
            for item in captured_tools[-1]
        )
    finally:
        await _shutdown(daemon_task, client)
