"""M3 integration checks for scheduled-task scope and resource enforcement."""

from __future__ import annotations

import asyncio
import textwrap
from contextlib import suppress
from pathlib import Path
from typing import Any

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
    policy_path.write_text(_base_policy(), encoding="utf-8")
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


async def _wait_for_audit_event(
    client: ControlClient,
    *,
    event_type: str,
    predicate: Any,
    timeout: float = 4.0,
) -> dict[str, Any]:
    end = asyncio.get_running_loop().time() + timeout
    latest: list[dict[str, Any]] = []
    while asyncio.get_running_loop().time() < end:
        result = await client.call("audit.query", {"event_type": event_type, "limit": 50})
        latest = [dict(event) for event in result.get("events", [])]
        for event in latest:
            if predicate(event):
                return event
        await asyncio.sleep(0.1)
    raise AssertionError(f"Timed out waiting for {event_type}: {latest}")


def _event_reason(event: dict[str, Any]) -> str:
    return str(
        event.get("reason")
        or event.get("reasoning")
        or event.get("data", {}).get("reason", "")
        or event.get("data", {}).get("reasoning", "")
    )


@pytest.mark.asyncio
async def test_m3_tainted_event_trigger_can_be_rejected_by_task_scope_policy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daemon_task, client = await _start_daemon(tmp_path, monkeypatch)
    try:
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
                "untrusted_payload_action": "reject",
            },
        )

        assert created["task_envelope"]["untrusted_payload_action"] == "reject"

        runs = await client.call(
            "task.trigger_event",
            {"event_type": "message.received", "payload": "raw user-controlled content"},
        )

        assert runs["count"] == 0
        assert runs["queued_confirmations"] == 0
        assert runs["blocked_runs"] == 1

        rejected = await _wait_for_audit_event(
            client,
            event_type="ToolRejected",
            predicate=lambda event: (
                "background:tainted_trigger_scope_block" in _event_reason(event)
            ),
        )
        assert "background:tainted_trigger_scope_block" in _event_reason(rejected)
    finally:
        await _shutdown_daemon(daemon_task, client)


@pytest.mark.asyncio
async def test_m3_task_resource_scope_blocks_cross_thread_message_send(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daemon_task, client = await _start_daemon(tmp_path, monkeypatch)
    try:
        created = await client.call(
            "task.create",
            {
                "name": "thread-reminder",
                "goal": "Reminder: post back into the allowed thread",
                "schedule": {
                    "kind": "event",
                    "expression": "message.received",
                    "event_type": "message.received",
                },
                "capability_snapshot": ["message.send"],
                "policy_snapshot_ref": "p1",
                "created_by": "alice",
                "workspace_id": "ws1",
                "delivery_target": {
                    "channel": "discord",
                    "recipient": "ops-room",
                    "thread_id": "thread-forbidden",
                },
                "resource_scope_ids": ["thread-allowed"],
            },
        )

        assert created["task_envelope"]["resource_scope_ids"] == ["thread-allowed"]

        runs = await client.call(
            "task.trigger_event",
            {"event_type": "message.received", "payload": "user supplied payload"},
        )

        assert runs["count"] == 0
        assert runs["queued_confirmations"] == 0
        assert runs["blocked_runs"] == 1

        rejected = await _wait_for_audit_event(
            client,
            event_type="ToolRejected",
            predicate=lambda event: "resource authorization failed" in _event_reason(event).lower()
            and "thread_id" in _event_reason(event),
        )
        assert "thread_id" in _event_reason(rejected)
    finally:
        await _shutdown_daemon(daemon_task, client)


@pytest.mark.asyncio
async def test_m3_task_resource_scope_prefix_allows_matching_thread_message_send(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daemon_task, client = await _start_daemon(tmp_path, monkeypatch)
    try:
        created = await client.call(
            "task.create",
            {
                "name": "thread-reminder-prefix",
                "goal": "Reminder: post back into the allowed thread prefix",
                "schedule": {
                    "kind": "event",
                    "expression": "message.received",
                    "event_type": "message.received",
                },
                "capability_snapshot": ["message.send"],
                "policy_snapshot_ref": "p1",
                "created_by": "alice",
                "workspace_id": "ws1",
                "delivery_target": {
                    "channel": "discord",
                    "recipient": "ops-room",
                    "thread_id": "thread-allowed:ops-room",
                },
                "resource_scope_prefixes": ["thread-allowed:"],
            },
        )

        assert created["task_envelope"]["resource_scope_prefixes"] == ["thread-allowed:"]

        runs = await client.call(
            "task.trigger_event",
            {"event_type": "message.received", "payload": "user supplied payload"},
        )

        assert runs["count"] == 1
        assert runs["queued_confirmations"] == 1
        assert runs["blocked_runs"] == 0
    finally:
        await _shutdown_daemon(daemon_task, client)
