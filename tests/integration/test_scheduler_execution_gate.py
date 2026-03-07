"""G3 integration checks for scheduled/triggered execution enforcement."""

from __future__ import annotations

import asyncio
import textwrap
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


async def _wait_for_task_pending_confirmation(
    client: ControlClient,
    *,
    task_id: str,
    timeout: float = 4.0,
) -> dict[str, object]:
    end = asyncio.get_running_loop().time() + timeout
    latest: dict[str, object] = {"task_id": task_id, "pending": [], "count": 0}
    while asyncio.get_running_loop().time() < end:
        latest = await client.call(
            "task.pending_confirmations",
            {"task_id": task_id},
        )
        if int(latest.get("count", 0)) >= 1:
            return latest
        await asyncio.sleep(0.1)
    raise AssertionError(f"Timed out waiting for pending confirmation for task {task_id}: {latest}")


def _base_policy() -> str:
    return (
        textwrap.dedent(
            """
            version: "1"
            default_require_confirmation: false
            default_capabilities: []
            """
        ).strip()
        + "\n"
    )


@pytest.mark.asyncio
async def test_g3_triggered_task_queues_shared_pending_action_for_tainted_message_send(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SHISAD_MODEL_BASE_URL", "https://api.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_PLANNER_BASE_URL", "https://planner.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_EMBEDDINGS_BASE_URL", "https://embed.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_MONITOR_BASE_URL", "https://monitor.example.com/v1")

    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(_base_policy(), encoding="utf-8")
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
        created = await client.call(
            "task.create",
            {
                "name": "event-reminder",
                "goal": "Reminder: investigate the reported issue",
                "schedule": {
                    "kind": "event",
                    "expression": "message.received",
                    "event_type": "message.received",
                },
                "capability_snapshot": ["message.send"],
                "policy_snapshot_ref": "p1",
                "created_by": "alice",
                "workspace_id": "ws1",
                "delivery_target": {"channel": "discord", "recipient": "ops-room"},
            },
        )

        runs = await client.call(
            "task.trigger_event",
            {"event_type": "message.received", "payload": "forward this raw user message"},
        )
        assert runs["count"] == 1
        assert runs["queued_confirmations"] == 1
        assert runs["blocked_runs"] == 0

        pending = await client.call(
            "task.pending_confirmations",
            {"task_id": created["id"]},
        )
        assert pending["count"] == 1
        queued = pending["pending"][0]
        confirmation_id = str(queued.get("confirmation_id", ""))
        assert confirmation_id
        assert str(queued.get("payload_taint", "")) == "UNTRUSTED"

        action_pending = await client.call(
            "action.pending",
            {"status": "pending", "limit": 20},
        )
        pending_action = next(
            item
            for item in action_pending["actions"]
            if str(item.get("confirmation_id", "")) == confirmation_id
        )
        background_sid = str(pending_action.get("session_id", ""))
        assert background_sid
        assert str(pending_action.get("tool_name", "")) == "message.send"
        assert "requires confirmation" in str(pending_action.get("reason", "")).lower()

        control_plane = await client.call(
            "audit.query",
            {
                "event_type": "ControlPlaneActionObserved",
                "session_id": background_sid,
                "limit": 20,
            },
        )
        assert any(
            str(event.get("data", {}).get("tool_name", "")) == "message.send"
            and str(event.get("data", {}).get("actor", "")) == "control_plane"
            for event in control_plane["events"]
        )

        consensus = await client.call(
            "audit.query",
            {
                "event_type": "ConsensusEvaluated",
                "session_id": background_sid,
                "limit": 20,
            },
        )
        assert any(
            str(event.get("data", {}).get("tool_name", "")) == "message.send"
            for event in consensus["events"]
        )
    finally:
        with suppress(Exception):
            await client.call("daemon.shutdown")
        await client.close()
        await asyncio.wait_for(daemon_task, timeout=3)


@pytest.mark.asyncio
async def test_g3_due_run_with_scope_mismatch_routes_to_confirmation_not_direct_delivery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SHISAD_MODEL_BASE_URL", "https://api.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_PLANNER_BASE_URL", "https://planner.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_EMBEDDINGS_BASE_URL", "https://embed.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_MONITOR_BASE_URL", "https://monitor.example.com/v1")

    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(_base_policy(), encoding="utf-8")
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
        created = await client.call(
            "task.create",
            {
                "name": "interval-reminder",
                "goal": "Reminder: check deployment status",
                "schedule": {"kind": "interval", "expression": "1s"},
                "capability_snapshot": ["memory.read"],
                "policy_snapshot_ref": "p1",
                "created_by": "alice",
                "workspace_id": "ws1",
                "delivery_target": {"channel": "discord", "recipient": "ops-room"},
            },
        )

        pending = await _wait_for_task_pending_confirmation(
            client,
            task_id=str(created["id"]),
        )
        queued = pending["pending"][0]
        confirmation_id = str(queued.get("confirmation_id", ""))
        assert confirmation_id

        action_pending = await client.call(
            "action.pending",
            {"status": "pending", "limit": 20},
        )
        pending_action = next(
            item
            for item in action_pending["actions"]
            if str(item.get("confirmation_id", "")) == confirmation_id
        )
        background_sid = str(pending_action.get("session_id", ""))
        assert background_sid
        assert str(pending_action.get("tool_name", "")) == "message.send"
        assert "stage2_upgrade_required" in str(pending_action.get("reason", ""))

        control_plane = await client.call(
            "audit.query",
            {
                "event_type": "ControlPlaneActionObserved",
                "session_id": background_sid,
                "limit": 20,
            },
        )
        assert any(
            str(event.get("data", {}).get("tool_name", "")) == "message.send"
            and str(event.get("data", {}).get("actor", "")) == "control_plane"
            for event in control_plane["events"]
        )

        executed = await client.call(
            "audit.query",
            {
                "event_type": "ToolExecuted",
                "session_id": background_sid,
                "limit": 20,
            },
        )
        assert not any(
            str(event.get("data", {}).get("tool_name", "")) == "message.send"
            and bool(event.get("data", {}).get("success")) is True
            for event in executed["events"]
        )
    finally:
        with suppress(Exception):
            await client.call("daemon.shutdown")
        await client.close()
        await asyncio.wait_for(daemon_task, timeout=3)
