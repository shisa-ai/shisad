"""M1 runtime integration checks for daemon wiring."""

from __future__ import annotations

import asyncio
import json
import sqlite3
from contextlib import suppress
from pathlib import Path

import pytest

from shisad.core.api.transport import ControlClient
from shisad.core.audit_segments import AuditIntegrityError
from shisad.core.config import DaemonConfig
from shisad.core.session import Session
from shisad.core.types import Capability, SessionId, UserId, WorkspaceId
from shisad.daemon.runner import run_daemon
from shisad.security.control_plane.schema import Origin
from shisad.security.control_plane.sidecar import (
    ControlPlaneRpcError,
    ControlPlaneSidecarClient,
)
from tests.helpers.daemon import (
    clear_remote_provider_env,
)
from tests.helpers.daemon import (
    wait_for_socket as _wait_for_socket,
)


@pytest.mark.asyncio
async def test_o4d_corrupt_main_audit_refuses_daemon_before_socket_start(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clear_remote_provider_env(monkeypatch)
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
    )
    audit_path = config.data_dir / "audit.jsonl"
    audit_path.parent.mkdir(parents=True)
    audit_path.write_text("{not-json}\n", encoding="utf-8")

    with pytest.raises(AuditIntegrityError):
        await run_daemon(config)
    assert not config.socket_path.exists()


@pytest.mark.asyncio
async def test_run_daemon_invokes_started_callback_after_socket_start(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clear_remote_provider_env(monkeypatch)

    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
        log_level="INFO",
    )
    started = asyncio.Event()

    daemon_task = asyncio.create_task(run_daemon(config, on_started=started.set))
    client = ControlClient(config.socket_path)

    try:
        await _wait_for_socket(config.socket_path)
        await asyncio.wait_for(started.wait(), timeout=3)
        assert config.socket_path.exists()
        await client.connect()
        status = await client.call("daemon.status")
        assert status["status"] == "running"
        assert status["audit"]["main"]["state"] == "verified"
        assert status["audit"]["main"]["verified"] is True
        assert status["audit"]["main"]["segment_count"] == 0
        assert status["audit"]["control_plane"]["state"] == "verified"
        assert status["audit"]["control_plane"]["verified"] is True
        assert "path" not in status["audit"]["control_plane"]
        assert "path" not in status["audit"]["main"]
        assert set(status["storage_upgrades"]) == {"memory", "timeline"}
        for upgrade in status["storage_upgrades"].values():
            assert upgrade["initialized"] is True
            assert upgrade["migrated"] is False
            assert upgrade["transaction_committed"] is True
            assert upgrade["from_version"] == 0
            assert upgrade["to_version"] == 1
            assert upgrade["backup_path"] is None
            assert upgrade["backup_preserved"] is False
        assert set(status["readiness"]) >= {
            "provider",
            "channels",
            "storage",
            "sandbox",
            "browser",
            "mcp",
            "search",
        }
        assert all(
            row["status"]
            in {
                "absent",
                "installed",
                "configured",
                "reachable",
                "authenticated",
                "verified",
                "degraded",
                "blocked",
            }
            for row in status["readiness"].values()
        )
    finally:
        with suppress(Exception):
            await client.call("daemon.shutdown")
        await client.close()
        await asyncio.wait_for(daemon_task, timeout=3)


@pytest.mark.asyncio
async def test_o4d_daemon_status_reports_live_control_plane_audit_latch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clear_remote_provider_env(monkeypatch)
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
    )
    daemon_task = asyncio.create_task(run_daemon(config))
    client = ControlClient(config.socket_path)
    control_plane = ControlPlaneSidecarClient(config.data_dir / "control_plane" / "sidecar.sock")
    audit_path = config.data_dir / "control_plane" / "audit.jsonl"
    origin = Origin(
        session_id="o4d-live-latch",
        user_id="user-1",
        workspace_id="ws-1",
        actor="planner",
        trust_level="untrusted",
    )

    try:
        await _wait_for_socket(config.socket_path)
        await client.connect()
        await control_plane.begin_precontent_plan(
            session_id=origin.session_id,
            goal="read a file",
            origin=origin,
            ttl_seconds=300,
            max_actions=2,
            capabilities={Capability.FILE_READ},
        )
        audit_path.chmod(0o400)
        with pytest.raises(ControlPlaneRpcError):
            await control_plane.begin_precontent_plan(
                session_id="o4d-live-latch-failure",
                goal="read another file",
                origin=origin.model_copy(update={"session_id": "o4d-live-latch-failure"}),
                ttl_seconds=300,
                max_actions=2,
                capabilities={Capability.FILE_READ},
            )
        audit_path.chmod(0o600)

        status = await client.call("daemon.status")
        assert status["audit"]["control_plane"]["state"] == "unavailable"
        assert status["audit"]["control_plane"]["reason_code"] == "audit.append_failed"
        assert status["audit"]["control_plane"]["verified"] is False
    finally:
        if audit_path.exists():
            audit_path.chmod(0o600)
        with suppress(Exception):
            await client.call("daemon.shutdown")
        await client.close()
        await asyncio.wait_for(daemon_task, timeout=3)


@pytest.mark.asyncio
async def test_o4c_status_retains_first_legacy_migration_results(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clear_remote_provider_env(monkeypatch)
    data_dir = tmp_path / "data"
    memory = data_dir / "memory_entries" / "memory.sqlite3"
    timeline = data_dir / "timeline" / "timeline.sqlite3"
    memory.parent.mkdir(parents=True)
    timeline.parent.mkdir(parents=True)
    with sqlite3.connect(memory) as connection:
        connection.execute(
            """
            CREATE TABLE memory_events (
                event_id TEXT PRIMARY KEY,
                entry_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                actor TEXT NOT NULL,
                ingress_handle_id TEXT,
                metadata_json TEXT NOT NULL
            )
            """
        )
    with sqlite3.connect(timeline) as connection:
        connection.execute(
            """
            CREATE TABLE timeline_rows (
                handle TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                episode_id TEXT NOT NULL,
                episode_index INTEGER NOT NULL,
                entry_id TEXT NOT NULL,
                role TEXT NOT NULL,
                content TEXT NOT NULL,
                snippet TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                user_id TEXT NOT NULL,
                workspace_id TEXT NOT NULL,
                channel TEXT NOT NULL,
                visibility TEXT NOT NULL,
                content_digest TEXT NOT NULL,
                evidence_ref_id TEXT NOT NULL,
                taint_labels TEXT NOT NULL,
                metadata_json TEXT NOT NULL,
                thread_id TEXT NOT NULL,
                related_memory_ids TEXT NOT NULL
            )
            """
        )
    config = DaemonConfig(
        data_dir=data_dir,
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
        for name, upgrade in status["storage_upgrades"].items():
            assert name in {"memory", "timeline"}
            assert upgrade["initialized"] is False
            assert upgrade["migrated"] is True
            assert upgrade["transaction_committed"] is True
            assert upgrade["from_version"] == 0
            assert upgrade["to_version"] == 1
            assert upgrade["backup_preserved"] is True
            assert Path(upgrade["backup_path"]).exists()
    finally:
        with suppress(Exception):
            await client.call("daemon.shutdown")
        await client.close()
        await asyncio.wait_for(daemon_task, timeout=3)


@pytest.mark.asyncio
async def test_run_daemon_started_callback_error_does_not_stop_daemon(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clear_remote_provider_env(monkeypatch)

    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
        log_level="INFO",
    )

    def _broken_callback() -> None:
        raise BrokenPipeError("output closed")

    daemon_task = asyncio.create_task(run_daemon(config, on_started=_broken_callback))
    client = ControlClient(config.socket_path)

    try:
        await _wait_for_socket(config.socket_path)
        await client.connect()
        status = await client.call("daemon.status")
        assert status["status"] == "running"
        assert not daemon_task.done()
    finally:
        with suppress(Exception):
            await client.call("daemon.shutdown")
        await client.close()
        await asyncio.wait_for(daemon_task, timeout=3)


@pytest.mark.asyncio
async def test_f3_doctor_reports_redacted_lock_and_component_storage_health(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clear_remote_provider_env(monkeypatch)
    config = DaemonConfig(
        data_dir=tmp_path / "d",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
        log_level="INFO",
    )
    daemon_task = asyncio.create_task(run_daemon(config))
    client = ControlClient(config.socket_path)

    try:
        await _wait_for_socket(config.socket_path)
        await client.connect()
        doctor = await client.call("doctor.check", {"component": "storage"})
        storage = doctor["checks"]["storage"]
        components = {row["component"]: row for row in storage["components"]}

        assert storage["lock"]["status"] == "verified"
        assert storage["lock"]["held"] is True
        assert {"scheduler", "skills", "selfmod", "evidence"} <= set(components)
        assert all(row["status"] in {"verified", "absent"} for row in components.values())
        assert str(config.data_dir) not in json.dumps(storage)
    finally:
        with suppress(Exception):
            await client.call("daemon.shutdown")
        await client.close()
        await asyncio.wait_for(daemon_task, timeout=3)


@pytest.mark.asyncio
async def test_f3_corrupt_scheduler_state_leaves_basic_conversation_usable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clear_remote_provider_env(monkeypatch)
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
        log_level="INFO",
    )
    scheduler_dir = config.data_dir / "tasks"
    scheduler_dir.mkdir(parents=True)
    corrupt = b"{not-json"
    (scheduler_dir / "tasks.json").write_bytes(corrupt)
    daemon_task = asyncio.create_task(run_daemon(config))
    client = ControlClient(config.socket_path)

    try:
        await _wait_for_socket(config.socket_path)
        await client.connect()
        doctor = await client.call("doctor.check", {"component": "storage"})
        storage = doctor["checks"]["storage"]
        scheduler = next(row for row in storage["components"] if row["component"] == "scheduler")
        assert scheduler["status"] == "degraded"
        assert scheduler["reason"]
        assert "conversation" in scheduler["remains_usable"]
        assert str(config.data_dir) not in json.dumps(scheduler)
        assert (scheduler_dir / "tasks.json").read_bytes() == corrupt

        created = await client.call(
            "session.create",
            {"channel": "cli", "user_id": "alice", "workspace_id": "ws1"},
        )
        reply = await client.call(
            "session.message",
            {"session_id": created["session_id"], "content": "hello"},
        )
        assert str(reply.get("response", "")).strip()
        assert reply.get("lockdown_level") == "normal"
        assert (scheduler_dir / "tasks.json").read_bytes() == corrupt
    finally:
        with suppress(Exception):
            await client.call("daemon.shutdown")
        await client.close()
        await asyncio.wait_for(daemon_task, timeout=3)


@pytest.mark.asyncio
async def test_daemon_registers_alarm_tool_and_derives_capability_grant_actor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clear_remote_provider_env(monkeypatch)
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
        assert str(reply["response"]).startswith(
            "[PLANNER FALLBACK: CONFIGURATION] No language model configured."
        )
        assert "Safe summary:" not in str(reply["response"])
        assert "summarize this text" not in str(reply["response"]).lower()
        assert "Configure a planner route or local planner preset" in str(reply["response"])
        assert "shisad doctor check --component provider" in str(reply["response"])
        assert "SHISAD_MODEL_REMOTE_ENABLED" not in str(reply["response"])

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
    clear_remote_provider_env(monkeypatch)

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
        assert str(response["response"]).startswith(
            "[PLANNER FALLBACK: CONFIGURATION] No language model configured."
        )
        assert "SHISAD_MODEL_REMOTE_ENABLED" not in str(response["response"])
    finally:
        with suppress(Exception):
            await client_2.call("daemon.shutdown")
        await client_2.close()
        await asyncio.wait_for(daemon_task_2, timeout=3)


@pytest.mark.asyncio
async def test_m6_session_terminate_makes_session_non_operable(
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
        created = await client.call(
            "session.create",
            {"channel": "cli", "user_id": "alice", "workspace_id": "ws1"},
        )
        sid = str(created["session_id"])

        terminated = await client.call(
            "session.terminate",
            {
                "session_id": sid,
                "channel": "cli",
                "user_id": "alice",
                "workspace_id": "ws1",
                "reason": "manual",
            },
        )
        assert terminated.get("terminated") is True

        with pytest.raises(RuntimeError, match="Unknown session"):
            await client.call(
                "session.message",
                {
                    "session_id": sid,
                    "channel": "cli",
                    "user_id": "alice",
                    "workspace_id": "ws1",
                    "content": "hello after terminate",
                },
            )
    finally:
        with suppress(Exception):
            await client.call("daemon.shutdown")
        await client.close()
        await asyncio.wait_for(daemon_task, timeout=3)


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
