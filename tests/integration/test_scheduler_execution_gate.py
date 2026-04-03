"""G3 integration checks for scheduled/triggered execution enforcement."""

from __future__ import annotations

import asyncio
import json
import textwrap
from collections.abc import Callable
from contextlib import suppress
from pathlib import Path
from typing import Any

import pytest

from shisad.core.api.transport import ControlClient
from shisad.core.config import DaemonConfig
from shisad.daemon.runner import run_daemon
from shisad.security.control_plane.consensus import (
    ActionMonitorVoter,
    VoteKind,
    VoterDecision,
)
from shisad.security.control_plane.schema import RiskTier


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


async def _wait_for_confirmation_to_leave_pending(
    client: ControlClient,
    *,
    task_id: str,
    confirmation_id: str,
    timeout: float = 4.0,
) -> dict[str, object]:
    end = asyncio.get_running_loop().time() + timeout
    latest: dict[str, object] = {"task_id": task_id, "pending": [], "count": 0}
    normalized_confirmation = confirmation_id.strip()
    while asyncio.get_running_loop().time() < end:
        latest = await client.call(
            "task.pending_confirmations",
            {"task_id": task_id},
        )
        if not any(
            str(item.get("confirmation_id", "")).strip() == normalized_confirmation
            for item in latest.get("pending", [])
        ):
            return latest
        await asyncio.sleep(0.1)
    message = f"Timed out waiting for confirmation to leave pending for task {task_id}: {latest}"
    raise AssertionError(message)


def _event_reason(event: dict[str, Any]) -> str:
    return str(
        event.get("reason")
        or event.get("reasoning")
        or event.get("data", {}).get("reason", "")
        or event.get("data", {}).get("reasoning", "")
    )


def _event_description(event: dict[str, Any]) -> str:
    return str(event.get("description") or event.get("data", {}).get("description", ""))


async def _wait_for_audit_event(
    client: ControlClient,
    *,
    event_type: str,
    session_id: str = "",
    predicate: Callable[[dict[str, Any]], bool],
    timeout: float = 4.0,
) -> dict[str, Any]:
    end = asyncio.get_running_loop().time() + timeout
    latest: list[dict[str, Any]] = []
    while asyncio.get_running_loop().time() < end:
        payload: dict[str, object] = {"event_type": event_type, "limit": 50}
        if session_id:
            payload["session_id"] = session_id
        result = await client.call("audit.query", payload)
        latest = [dict(event) for event in result.get("events", [])]
        for event in latest:
            if predicate(event):
                return event
        await asyncio.sleep(0.1)
    raise AssertionError(f"Timed out waiting for {event_type}: {latest}")


async def _wait_for_task_session_id(
    client: ControlClient,
    *,
    task_id: str,
    timeout: float = 4.0,
) -> str:
    event = await _wait_for_audit_event(
        client,
        event_type="TaskTriggered",
        predicate=lambda item: (
            str(item.get("data", {}).get("task_id", "")) == task_id
            and bool(str(item.get("session_id", "")).strip())
        ),
        timeout=timeout,
    )
    session_id = str(event.get("session_id", "")).strip()
    if not session_id:
        raise AssertionError(f"TaskTriggered missing session_id for task {task_id}: {event}")
    return session_id


def _decision_nonce_for_confirmation(
    *,
    pending_actions: list[dict[str, Any]],
    confirmation_id: str,
) -> str:
    for item in pending_actions:
        if str(item.get("confirmation_id", "")) == confirmation_id:
            return str(item.get("decision_nonce", "")).strip()
    return ""


async def _confirm_pending_action(
    client: ControlClient,
    *,
    confirmation_id: str,
    decision_nonce: str,
    reason: str,
    timeout: float = 8.0,
) -> dict[str, Any]:
    end = asyncio.get_running_loop().time() + timeout
    latest: dict[str, Any] = {}
    while asyncio.get_running_loop().time() < end:
        latest = await client.call(
            "action.confirm",
            {
                "confirmation_id": confirmation_id,
                "decision_nonce": decision_nonce,
                "reason": reason,
            },
        )
        if str(latest.get("reason", "")) != "cooldown_active":
            return latest
        retry_after = float(latest.get("retry_after_seconds", 0.1) or 0.1)
        await asyncio.sleep(max(0.05, retry_after))
    raise AssertionError(
        f"Timed out waiting for confirmation cooldown to expire: {confirmation_id} latest={latest}"
    )


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


@pytest.mark.asyncio
async def test_g3_triggered_task_queues_shared_pending_action_for_tainted_message_send(
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
        await _shutdown_daemon(daemon_task, client)


@pytest.mark.asyncio
async def test_g3_due_run_with_domain_scope_mismatch_routes_to_confirmation_not_direct_delivery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daemon_task, client = await _start_daemon(tmp_path, monkeypatch)
    try:
        created = await client.call(
            "task.create",
            {
                "name": "interval-reminder",
                "goal": "Reminder: check deployment status",
                "schedule": {"kind": "interval", "expression": "1s"},
                "capability_snapshot": ["message.send"],
                "policy_snapshot_ref": "p1",
                "created_by": "alice",
                "workspace_id": "ws1",
                "allowed_domains": ["example.com"],
                "delivery_target": {
                    "channel": "discord",
                    "recipient": "https://hooks.example.net/alert",
                },
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
        assert "background:domain_scope_mismatch" in str(pending_action.get("reason", ""))

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
        await _shutdown_daemon(daemon_task, client)


@pytest.mark.asyncio
async def test_g3_due_run_allowed_recipient_mismatch_routes_to_confirmation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daemon_task, client = await _start_daemon(tmp_path, monkeypatch)
    try:
        created = await client.call(
            "task.create",
            {
                "name": "recipient-guard",
                "goal": "Reminder: check deployment status",
                "schedule": {"kind": "interval", "expression": "1s"},
                "capability_snapshot": ["message.send"],
                "policy_snapshot_ref": "p1",
                "created_by": "alice",
                "workspace_id": "ws1",
                "allowed_recipients": ["ops-room-2"],
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
        assert "background:recipient_scope_mismatch" in str(pending_action.get("reason", ""))
    finally:
        await _shutdown_daemon(daemon_task, client)


@pytest.mark.asyncio
async def test_g3_task_confirmation_replay_updates_scheduler_state_and_outcome(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daemon_task, client = await _start_daemon(tmp_path, monkeypatch)
    try:
        created = await client.call(
            "task.create",
            {
                "name": "confirm-replay",
                "goal": "Reminder: check deployment status",
                "schedule": {"kind": "interval", "expression": "1s"},
                "capability_snapshot": ["message.send"],
                "policy_snapshot_ref": "p1",
                "created_by": "alice",
                "workspace_id": "ws1",
                "allowed_recipients": ["ops-room-2"],
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
        decision_nonce = _decision_nonce_for_confirmation(
            pending_actions=[dict(item) for item in action_pending["actions"]],
            confirmation_id=confirmation_id,
        )
        assert decision_nonce

        confirmed = await _confirm_pending_action(
            client,
            confirmation_id=confirmation_id,
            decision_nonce=decision_nonce,
            reason="approve for regression test",
        )
        assert confirmed["confirmed"] is False
        assert str(confirmed.get("confirmation_id", "")) == confirmation_id
        assert str(confirmed.get("status", "")) == "failed"
        assert str(confirmed.get("status_reason", "")) == "approve for regression test"

        remaining = await _wait_for_confirmation_to_leave_pending(
            client,
            task_id=str(created["id"]),
            confirmation_id=confirmation_id,
        )
        assert not any(
            str(item.get("confirmation_id", "")) == confirmation_id for item in remaining["pending"]
        )

        tasks_payload = json.loads(
            (tmp_path / "data" / "tasks" / "tasks.json").read_text(encoding="utf-8")
        )
        task_row = next(item for item in tasks_payload if str(item.get("id", "")) == created["id"])
        assert int(task_row.get("failure_count", 0)) >= 1
        assert int(task_row.get("success_count", 0)) == 0

        pending_payload = json.loads(
            (tmp_path / "data" / "tasks" / "pending_confirmations.json").read_text(encoding="utf-8")
        )
        rows = list(pending_payload.get(str(created["id"]), []))
        matching = next(
            item for item in rows if str(item.get("confirmation_id", "")) == confirmation_id
        )
        assert str(matching.get("status", "")) == "failed"
        assert str(matching.get("status_reason", "")) == "approve for regression test"
    finally:
        await _shutdown_daemon(daemon_task, client)


@pytest.mark.asyncio
async def test_g3_due_run_with_capability_mismatch_stays_non_confirmable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daemon_task, client = await _start_daemon(tmp_path, monkeypatch)
    try:
        created = await client.call(
            "task.create",
            {
                "name": "restricted-reminder",
                "goal": "Reminder: check deployment status",
                "schedule": {"kind": "interval", "expression": "1s"},
                "capability_snapshot": ["memory.read"],
                "policy_snapshot_ref": "p1",
                "created_by": "alice",
                "workspace_id": "ws1",
                "delivery_target": {"channel": "discord", "recipient": "ops-room"},
            },
        )

        background_sid = await _wait_for_task_session_id(client, task_id=str(created["id"]))

        pending = await client.call(
            "task.pending_confirmations",
            {"task_id": created["id"]},
        )
        assert pending["count"] == 0

        action_pending = await client.call("action.pending", {"status": "pending", "limit": 20})
        assert not any(
            str(item.get("session_id", "")) == background_sid for item in action_pending["actions"]
        )

        rejected = await _wait_for_audit_event(
            client,
            event_type="ToolRejected",
            session_id=background_sid,
            predicate=lambda event: "trace:stage2_upgrade_required" in _event_reason(event),
        )
        assert "trace:stage2_upgrade_required" in _event_reason(rejected)
    finally:
        await _shutdown_daemon(daemon_task, client)


@pytest.mark.asyncio
async def test_g3_due_run_control_plane_block_vote_does_not_become_confirmable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _forced_block_vote(self: ActionMonitorVoter, data: object) -> VoterDecision:
        _ = data
        return VoterDecision(
            voter="ActionMonitorVoter",
            decision=VoteKind.BLOCK,
            risk_tier=RiskTier.HIGH,
            reason_codes=["test:forced_background_block"],
        )

    monkeypatch.setattr(ActionMonitorVoter, "cast_vote", _forced_block_vote)
    daemon_task, client = await _start_daemon(tmp_path, monkeypatch)
    try:
        created = await client.call(
            "task.create",
            {
                "name": "blocked-reminder",
                "goal": "Reminder: check deployment status",
                "schedule": {"kind": "interval", "expression": "1s"},
                "capability_snapshot": ["memory.read"],
                "policy_snapshot_ref": "p1",
                "created_by": "alice",
                "workspace_id": "ws1",
                "delivery_target": {"channel": "discord", "recipient": "ops-room"},
            },
        )

        background_sid = await _wait_for_task_session_id(client, task_id=str(created["id"]))

        pending = await client.call(
            "task.pending_confirmations",
            {"task_id": created["id"]},
        )
        assert pending["count"] == 0

        consensus = await _wait_for_audit_event(
            client,
            event_type="ConsensusEvaluated",
            session_id=background_sid,
            predicate=lambda event: any(
                str(vote.get("voter", "")) == "ActionMonitorVoter"
                and str(vote.get("decision", "")) == "BLOCK"
                and "test:forced_background_block" in list(vote.get("reason_codes", []))
                for vote in event.get("data", {}).get("votes", [])
            ),
        )
        assert any(
            str(vote.get("voter", "")) == "ActionMonitorVoter"
            and str(vote.get("decision", "")) == "BLOCK"
            and "test:forced_background_block" in list(vote.get("reason_codes", []))
            for vote in consensus.get("data", {}).get("votes", [])
        )

        rejected = await _wait_for_audit_event(
            client,
            event_type="ToolRejected",
            session_id=background_sid,
            predicate=lambda event: "ActionMonitorVoter" in _event_reason(event),
        )
        assert "ActionMonitorVoter" in _event_reason(rejected)
    finally:
        await _shutdown_daemon(daemon_task, client)


@pytest.mark.asyncio
async def test_g3_due_run_honors_caution_and_full_lockdown(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daemon_task, client = await _start_daemon(tmp_path, monkeypatch)
    try:
        created = await client.call(
            "task.create",
            {
                "name": "lockdown-reminder",
                "goal": "Reminder: check deployment status",
                "schedule": {"kind": "interval", "expression": "1s"},
                "capability_snapshot": ["message.send"],
                "policy_snapshot_ref": "p1",
                "created_by": "alice",
                "workspace_id": "ws1",
                "delivery_target": {"channel": "discord", "recipient": "ops-room"},
            },
        )

        background_sid = await _wait_for_task_session_id(client, task_id=str(created["id"]))

        await _wait_for_audit_event(
            client,
            event_type="ToolExecuted",
            session_id=background_sid,
            predicate=lambda _event: True,
        )

        await client.call(
            "lockdown.set",
            {"session_id": background_sid, "action": "caution", "reason": "manual review"},
        )

        caution_rejected = await _wait_for_audit_event(
            client,
            event_type="ToolRejected",
            session_id=background_sid,
            predicate=lambda event: "Missing capabilities: message.send" in _event_reason(event),
        )
        assert "Missing capabilities: message.send" in _event_reason(caution_rejected)

        await client.call(
            "lockdown.set",
            {
                "session_id": background_sid,
                "action": "full_lockdown",
                "reason": "incident",
            },
        )

        locked_rejected = await _wait_for_audit_event(
            client,
            event_type="ToolRejected",
            session_id=background_sid,
            predicate=lambda event: _event_reason(event) == "session_in_lockdown",
        )
        assert _event_reason(locked_rejected) == "session_in_lockdown"

        pending = await client.call(
            "task.pending_confirmations",
            {"task_id": created["id"]},
        )
        assert pending["count"] == 0
    finally:
        await _shutdown_daemon(daemon_task, client)


@pytest.mark.asyncio
async def test_g3_triggered_task_missing_delivery_target_degrades_without_pending_confirmation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daemon_task, client = await _start_daemon(tmp_path, monkeypatch)
    try:
        created = await client.call(
            "task.create",
            {
                "name": "broken-event-reminder",
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
            },
        )

        runs = await client.call(
            "task.trigger_event",
            {"event_type": "message.received", "payload": "forward this raw user message"},
        )
        assert runs["count"] == 0
        assert runs["queued_confirmations"] == 0
        assert runs["blocked_runs"] == 1

        pending = await client.call(
            "task.pending_confirmations",
            {"task_id": created["id"]},
        )
        assert pending["count"] == 0

        anomaly = await _wait_for_audit_event(
            client,
            event_type="AnomalyReported",
            predicate=lambda event: "missing delivery target" in _event_description(event).lower(),
        )
        assert "missing delivery target" in _event_description(anomaly).lower()
    finally:
        await _shutdown_daemon(daemon_task, client)
