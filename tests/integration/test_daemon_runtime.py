"""M1 runtime integration checks for daemon wiring."""

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


@pytest.mark.asyncio
async def test_daemon_registers_alarm_tool_and_derives_capability_grant_actor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SHISAD_MODEL_BASE_URL", "https://api.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_PLANNER_BASE_URL", "https://planner.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_EMBEDDINGS_BASE_URL", "https://embed.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_MONITOR_BASE_URL", "https://monitor.example.com/v1")

    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
        log_level="INFO",
    )

    daemon_task = asyncio.create_task(run_daemon(config))
    client = ControlClient(config.socket_path)

    try:
        await _wait_for_socket(config.socket_path)
        await client.connect()

        status = await client.call("daemon.status")
        tools = set(status.get("tools_registered", []))
        assert "retrieve_rag" in tools
        assert "report_anomaly" in tools

        created = await client.call(
            "session.create",
            {"channel": "cli", "user_id": "alice", "workspace_id": "ws1"},
        )
        sid = created["session_id"]

        reply = await client.call(
            "session.message",
            {
                "session_id": sid,
                "channel": "cli",
                "user_id": "alice",
                "workspace_id": "ws1",
                "content": "summarize this text",
            },
        )
        assert "SYSTEM INSTRUCTIONS (TRUSTED)" in reply["response"]
        assert "EXTERNAL CONTENT (UNTRU" in reply["response"]

        grant = await client.call(
            "session.grant_capabilities",
            {
                "session_id": sid,
                "capabilities": ["http.request"],
                "actor": "agent",  # should be ignored by server
                "reason": "runtime-test",
            },
        )
        assert grant["granted"]

        await asyncio.sleep(0.05)
        audit = await client.call("audit.query", {"event_type": "CapabilityGranted", "limit": 10})
        events = audit.get("events", [])
        assert events
        latest = events[0]
        granted_by = latest["data"].get("granted_by", "")
        assert granted_by.startswith("uid:")
        assert granted_by != "agent"
    finally:
        with suppress(Exception):
            await client.call("daemon.shutdown")
        await client.close()
        await asyncio.wait_for(daemon_task, timeout=3)
