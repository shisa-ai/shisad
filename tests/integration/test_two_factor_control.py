"""Integration coverage for daemon-backed 2FA enrollment management."""

from __future__ import annotations

import asyncio
from contextlib import suppress
from pathlib import Path

import pytest

from shisad.core.api.transport import ControlClient
from shisad.core.approval import generate_totp_code
from shisad.core.config import DaemonConfig
from shisad.daemon.runner import run_daemon


async def _wait_for_socket(path: Path, timeout: float = 5.0) -> None:
    end = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < end:
        if path.exists():
            return
        await asyncio.sleep(0.01)
    raise TimeoutError(f"Timed out waiting for socket {path}")


def _configure_model_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SHISAD_MODEL_BASE_URL", "https://api.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_PLANNER_BASE_URL", "https://planner.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_EMBEDDINGS_BASE_URL", "https://embed.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_MONITOR_BASE_URL", "https://monitor.example.com/v1")


async def _start_daemon(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[asyncio.Task[None], ControlClient]:
    _configure_model_env(monkeypatch)
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text('version: "1"\ndefault_require_confirmation: false\n', encoding="utf-8")
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=policy_path,
        log_level="INFO",
    )
    daemon_task = asyncio.create_task(run_daemon(config))
    client = ControlClient(config.socket_path)
    await _wait_for_socket(config.socket_path)
    await client.connect()
    return daemon_task, client


async def _shutdown_daemon(daemon_task: asyncio.Task[None], client: ControlClient) -> None:
    with suppress(Exception):
        await client.call("daemon.shutdown")
    await client.close()
    await asyncio.wait_for(daemon_task, timeout=3)


@pytest.mark.asyncio
async def test_two_factor_register_list_revoke_persists_across_restart(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daemon_task, client = await _start_daemon(tmp_path, monkeypatch)
    try:
        started = await client.call(
            "2fa.register_begin",
            {"method": "totp", "user_id": "alice", "name": "ops-laptop"},
        )
        assert started["started"] is True
        confirm = await client.call(
            "2fa.register_confirm",
            {
                "enrollment_id": started["enrollment_id"],
                "verify_code": generate_totp_code(str(started["secret"])),
            },
        )
        assert confirm["registered"] is True
        listed = await client.call("2fa.list", {"user_id": "alice"})
        assert listed["count"] == 1
        assert listed["entries"][0]["principal_id"] == "ops-laptop"
        assert listed["entries"][0]["credential_id"] == confirm["credential_id"]
    finally:
        await _shutdown_daemon(daemon_task, client)

    daemon_task, client = await _start_daemon(tmp_path, monkeypatch)
    try:
        listed = await client.call("2fa.list", {"user_id": "alice"})
        assert listed["count"] == 1
        revoke = await client.call(
            "2fa.revoke",
            {
                "method": "totp",
                "user_id": "alice",
                "credential_id": listed["entries"][0]["credential_id"],
            },
        )
        assert revoke["revoked"] is True
        assert revoke["removed"] == 1
        listed_after = await client.call("2fa.list", {"user_id": "alice"})
        assert listed_after["count"] == 0
    finally:
        await _shutdown_daemon(daemon_task, client)
