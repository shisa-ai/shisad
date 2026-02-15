"""M4 integration coverage for clean-room workflow and pairing proposals."""

from __future__ import annotations

import asyncio
from contextlib import suppress
from pathlib import Path

import pytest

from shisad.core.api.transport import ControlClient
from shisad.core.config import DaemonConfig
from shisad.daemon.runner import run_daemon


async def _wait_for_socket(path: Path, timeout: float = 2.0) -> None:
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


async def _start_daemon(
    tmp_path: Path,
    **kwargs: object,
) -> tuple[asyncio.Task[None], ControlClient, DaemonConfig]:
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
        log_level="INFO",
        **kwargs,
    )
    daemon_task = asyncio.create_task(run_daemon(config))
    client = ControlClient(config.socket_path)
    await _wait_for_socket(config.socket_path)
    await client.connect()
    return daemon_task, client, config


async def _shutdown(daemon_task: asyncio.Task[None], client: ControlClient) -> None:
    with suppress(Exception):
        await client.call("daemon.shutdown")
    await client.close()
    await asyncio.wait_for(daemon_task, timeout=3)


@pytest.mark.asyncio
async def test_m4_cleanroom_mode_transition_rejects_tainted_history(
    model_env: None,
    tmp_path: Path,
) -> None:
    daemon_task, client, _config = await _start_daemon(tmp_path)
    try:
        created = await client.call("session.create", {"channel": "cli", "user_id": "alice"})
        sid = created["session_id"]
        _ = await client.call(
            "session.message",
            {"session_id": sid, "content": "hello from a normal session"},
        )
        mode_update = await client.call(
            "session.set_mode",
            {"session_id": sid, "mode": "admin_cleanroom"},
        )
        assert mode_update["changed"] is False
        assert mode_update["reason"] == "tainted_transcript_history"
    finally:
        await _shutdown(daemon_task, client)


@pytest.mark.asyncio
async def test_m4_cleanroom_session_message_is_proposal_only_and_rejects_tainted_payload(
    model_env: None,
    tmp_path: Path,
) -> None:
    daemon_task, client, _config = await _start_daemon(tmp_path)
    try:
        created = await client.call(
            "session.create",
            {
                "channel": "cli",
                "user_id": "admin",
                "workspace_id": "ops",
                "mode": "admin_cleanroom",
            },
        )
        sid = created["session_id"]

        clean = await client.call(
            "session.message",
            {"session_id": sid, "content": "review pending pairing proposals"},
        )
        assert clean["session_mode"] == "admin_cleanroom"
        assert clean["proposal_only"] is True
        assert clean["executed_actions"] == 0

        tainted = await client.call(
            "session.message",
            {"session_id": sid, "content": "api key sk-ABCDEFGHIJKLMNOPQRSTUV123456"},
        )
        assert tainted["proposal_only"] is True
        assert any(
            "cleanroom_tainted_payload" in reason
            for reason in tainted.get("cleanroom_block_reasons", [])
        )
    finally:
        await _shutdown(daemon_task, client)


@pytest.mark.asyncio
async def test_m4_pairing_proposal_uses_pairing_request_artifacts(
    model_env: None,
    tmp_path: Path,
) -> None:
    daemon_task, client, _config = await _start_daemon(tmp_path)
    try:
        ingest = await client.call(
            "channel.ingest",
            {
                "message": {
                    "channel": "discord",
                    "external_user_id": "attacker-user",
                    "workspace_hint": "guild-1",
                    "content": "hello",
                }
            },
        )
        assert "Pairing request recorded" in ingest["response"]

        proposal = await client.call(
            "channel.pairing_propose",
            {"channel": "discord", "limit": 20},
        )
        assert proposal["applied"] is False
        assert proposal["count"] >= 1
        assert "discord" in proposal["config_patch"]
        assert "attacker-user" in proposal["config_patch"]["discord"]
        assert Path(proposal["proposal_path"]).exists()
    finally:
        await _shutdown(daemon_task, client)
