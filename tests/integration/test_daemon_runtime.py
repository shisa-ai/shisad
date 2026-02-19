"""M1 runtime integration checks for daemon wiring."""

from __future__ import annotations

import asyncio
from contextlib import suppress
from pathlib import Path

import pytest

from shisad.core.api.transport import ControlClient
from shisad.core.config import DaemonConfig
from shisad.core.session import Session
from shisad.core.types import Capability, SessionId, UserId, WorkspaceId
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
    (tmp_path / "policy.yaml").write_text(
        "\n".join(
            [
                'version: "1"',
                "default_deny: true",
                "default_require_confirmation: false",
                "default_capabilities:",
                "  - file.read",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

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
        assert "Safe summary:" in reply["response"]
        assert "summarize this text" in reply["response"].lower()

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


@pytest.mark.asyncio
async def test_m3_session_persists_across_daemon_restart(
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

    daemon_task_1 = asyncio.create_task(run_daemon(config))
    client_1 = ControlClient(config.socket_path)
    sid = ""
    try:
        await _wait_for_socket(config.socket_path)
        await client_1.connect()
        created = await client_1.call(
            "session.create",
            {"channel": "cli", "user_id": "alice", "workspace_id": "ws1"},
        )
        sid = str(created["session_id"])
        assert sid
        _ = await client_1.call(
            "session.message",
            {
                "session_id": sid,
                "channel": "cli",
                "user_id": "alice",
                "workspace_id": "ws1",
                "content": "first turn",
            },
        )
    finally:
        with suppress(Exception):
            await client_1.call("daemon.shutdown")
        await client_1.close()
        await asyncio.wait_for(daemon_task_1, timeout=3)

    daemon_task_2 = asyncio.create_task(run_daemon(config))
    client_2 = ControlClient(config.socket_path)
    try:
        await _wait_for_socket(config.socket_path)
        await client_2.connect()
        listed = await client_2.call("session.list")
        sessions = listed.get("sessions", [])
        assert any(str(row.get("id", "")) == sid for row in sessions)
        response = await client_2.call(
            "session.message",
            {
                "session_id": sid,
                "channel": "cli",
                "user_id": "alice",
                "workspace_id": "ws1",
                "content": "second turn",
            },
        )
        assert "safe summary:" in str(response["response"]).lower()
    finally:
        with suppress(Exception):
            await client_2.call("daemon.shutdown")
        await client_2.close()
        await asyncio.wait_for(daemon_task_2, timeout=3)


@pytest.mark.asyncio
async def test_m6_restored_legacy_session_backfills_current_policy_capabilities(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SHISAD_MODEL_BASE_URL", "https://api.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_PLANNER_BASE_URL", "https://planner.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_EMBEDDINGS_BASE_URL", "https://embed.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_MONITOR_BASE_URL", "https://monitor.example.com/v1")

    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        "\n".join(
            [
                'version: "1"',
                "default_require_confirmation: false",
                "default_capabilities:",
                "  - memory.read",
                "  - file.read",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    state_dir = tmp_path / "data" / "sessions" / "state"
    state_dir.mkdir(parents=True, exist_ok=True)
    legacy = Session(
        id=SessionId("legacy-empty-integration"),
        channel="cli",
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("ws1"),
        capabilities=set(),
        metadata={"trust_level": "trusted"},
    )
    (state_dir / f"{legacy.id}.json").write_text(
        legacy.model_dump_json(indent=2),
        encoding="utf-8",
    )

    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=policy_path,
        log_level="INFO",
    )

    daemon_task = asyncio.create_task(run_daemon(config))
    client = ControlClient(config.socket_path)

    try:
        await _wait_for_socket(config.socket_path)
        await client.connect()
        listed = await client.call("session.list")
        sessions = listed.get("sessions", [])
        row = next(
            (item for item in sessions if str(item.get("id", "")) == str(legacy.id)),
            None,
        )
        assert row is not None
        capabilities = set(row.get("capabilities", []))
        assert Capability.MEMORY_READ.value in capabilities
        assert Capability.FILE_READ.value in capabilities
    finally:
        with suppress(Exception):
            await client.call("daemon.shutdown")
        await client.close()
        await asyncio.wait_for(daemon_task, timeout=3)


@pytest.mark.asyncio
async def test_m6_policy_default_session_syncs_to_empty_default_capabilities_on_restore(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SHISAD_MODEL_BASE_URL", "https://api.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_PLANNER_BASE_URL", "https://planner.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_EMBEDDINGS_BASE_URL", "https://embed.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_MONITOR_BASE_URL", "https://monitor.example.com/v1")

    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        "\n".join(
            [
                'version: "1"',
                "default_require_confirmation: false",
                "default_capabilities: []",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    state_dir = tmp_path / "data" / "sessions" / "state"
    state_dir.mkdir(parents=True, exist_ok=True)
    policy_default = Session(
        id=SessionId("policy-default-empty-integration"),
        channel="cli",
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("ws1"),
        capabilities={Capability.FILE_READ, Capability.HTTP_REQUEST},
        metadata={"capability_sync_mode": "policy_default"},
    )
    (state_dir / f"{policy_default.id}.json").write_text(
        policy_default.model_dump_json(indent=2),
        encoding="utf-8",
    )

    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=policy_path,
        log_level="INFO",
    )

    daemon_task = asyncio.create_task(run_daemon(config))
    client = ControlClient(config.socket_path)

    try:
        await _wait_for_socket(config.socket_path)
        await client.connect()
        listed = await client.call("session.list")
        sessions = listed.get("sessions", [])
        row = next(
            (item for item in sessions if str(item.get("id", "")) == str(policy_default.id)),
            None,
        )
        assert row is not None
        capabilities = set(row.get("capabilities", []))
        assert capabilities == set()
    finally:
        with suppress(Exception):
            await client.call("daemon.shutdown")
        await client.close()
        await asyncio.wait_for(daemon_task, timeout=3)
