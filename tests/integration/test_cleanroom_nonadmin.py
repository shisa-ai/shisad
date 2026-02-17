"""Integration coverage for non-admin clean-room rejection paths."""

from __future__ import annotations

import asyncio
from contextlib import suppress
from pathlib import Path

import pytest

from shisad.core.api.transport import ControlClient
from shisad.core.config import DaemonConfig
from shisad.daemon.handlers._impl import HandlerImplementation
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


@pytest.fixture
def force_non_admin_peer(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        HandlerImplementation,
        "_is_admin_rpc_peer",
        staticmethod(lambda params: False),  # type: ignore[return-value]
    )


async def _start_daemon(tmp_path: Path) -> tuple[asyncio.Task[None], ControlClient]:
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
        log_level="INFO",
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
async def test_m3_non_admin_session_create_rejects_admin_cleanroom_mode(
    model_env: None,
    force_non_admin_peer: None,
    tmp_path: Path,
) -> None:
    daemon_task, client = await _start_daemon(tmp_path)
    try:
        with pytest.raises(
            RuntimeError,
            match="admin_cleanroom mode requires trusted admin ingress",
        ):
            await client.call(
                "session.create",
                {
                    "channel": "cli",
                    "user_id": "alice",
                    "workspace_id": "ops",
                    "mode": "admin_cleanroom",
                },
            )
    finally:
        await _shutdown(daemon_task, client)


@pytest.mark.asyncio
async def test_m3_non_admin_session_set_mode_rejects_admin_cleanroom(
    model_env: None,
    force_non_admin_peer: None,
    tmp_path: Path,
) -> None:
    daemon_task, client = await _start_daemon(tmp_path)
    try:
        created = await client.call(
            "session.create",
            {"channel": "cli", "user_id": "alice", "workspace_id": "ops"},
        )
        sid = str(created["session_id"])
        with pytest.raises(
            RuntimeError,
            match="admin_cleanroom mode requires trusted admin ingress",
        ):
            await client.call(
                "session.set_mode",
                {
                    "session_id": sid,
                    "mode": "admin_cleanroom",
                },
            )
    finally:
        await _shutdown(daemon_task, client)
