"""v0.4 behavioral extensions for background execution and admin self-modification."""

from __future__ import annotations

import asyncio
import hashlib
import json
import subprocess
import sys
from collections.abc import Callable
from contextlib import suppress
from pathlib import Path
from typing import Any

import pytest
import yaml

from shisad.channels.base import DeliveryTarget
from shisad.channels.delivery import ChannelDeliveryService, DeliveryResult
from shisad.core.api.transport import ControlClient
from shisad.core.config import DaemonConfig
from shisad.core.planner import Planner, PlannerOutput, PlannerResult
from shisad.core.transcript import TranscriptStore
from shisad.daemon.runner import run_daemon


def _base_policy() -> str:
    return 'version: "1"\ndefault_require_confirmation: false\n'


async def _wait_for_socket(path: Path, timeout: float = 2.0) -> None:
    end = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < end:
        if path.exists():
            return
        await asyncio.sleep(0.01)
    raise TimeoutError(f"Timed out waiting for socket {path}")


async def _start_daemon(
    tmp_path: Path,
    *,
    allowed_signers_path: Path | None = None,
    policy_text: str | None = None,
    config_overrides: dict[str, Any] | None = None,
) -> tuple[asyncio.Task[None], ControlClient, DaemonConfig]:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(policy_text or _base_policy(), encoding="utf-8")
    config_kwargs: dict[str, Any] = {
        "data_dir": tmp_path / "data",
        "socket_path": tmp_path / "control.sock",
        "policy_path": policy_path,
        "log_level": "INFO",
    }
    if allowed_signers_path is not None:
        config_kwargs["selfmod_allowed_signers_path"] = allowed_signers_path
    if config_overrides:
        config_kwargs.update(config_overrides)
    config = DaemonConfig(**config_kwargs)
    daemon_task = asyncio.create_task(run_daemon(config))
    client = ControlClient(config.socket_path)
    await _wait_for_socket(config.socket_path)
    await client.connect()
    return daemon_task, client, config


async def _shutdown_daemon(daemon_task: asyncio.Task[None], client: ControlClient) -> None:
    with suppress(Exception):
        await client.call("daemon.shutdown")
    await client.close()
    await asyncio.wait_for(daemon_task, timeout=3)


async def _wait_for_audit_event(
    client: ControlClient,
    *,
    event_type: str,
    predicate: Callable[[dict[str, Any]], bool],
    session_id: str = "",
    timeout: float = 4.0,
) -> dict[str, Any]:
    end = asyncio.get_running_loop().time() + timeout
    latest: list[dict[str, Any]] = []
    while asyncio.get_running_loop().time() < end:
        payload: dict[str, Any] = {"event_type": event_type, "limit": 50}
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
        predicate=lambda item: str(item.get("data", {}).get("task_id", "")) == task_id
        and bool(str(item.get("session_id", "")).strip()),
        timeout=timeout,
    )
    session_id = str(event.get("session_id", "")).strip()
    if not session_id:
        raise AssertionError(f"TaskTriggered missing session_id for task {task_id}: {event}")
    return session_id


async def _wait_for_task_pending_confirmation(
    client: ControlClient,
    *,
    task_id: str,
    timeout: float = 4.0,
) -> dict[str, Any]:
    end = asyncio.get_running_loop().time() + timeout
    latest: dict[str, Any] = {"task_id": task_id, "pending": [], "count": 0}
    while asyncio.get_running_loop().time() < end:
        latest = await client.call("task.pending_confirmations", {"task_id": task_id})
        if int(latest.get("count", 0)) >= 1:
            return latest
        await asyncio.sleep(0.1)
    raise AssertionError(
        f"Timed out waiting for pending confirmation for task {task_id}: {latest}"
    )


def _fake_coding_agent_command(agent_name: str) -> str:
    script = Path(__file__).resolve().parents[1] / "fixtures" / "fake_acp_agent.py"
    return f"{sys.executable} {script} --agent-name {agent_name}"


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
                        "parameters": [
                            {"name": "query", "type": "string", "required": True}
                        ],
                        "destinations": ["api.good.example"],
                    }
                ],
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    (payload_root / "SKILL.md").write_text(
        "Use the lookup tool for schedule reads.\n",
        encoding="utf-8",
    )
    files: list[dict[str, Any]] = []
    for path in sorted(payload_root.rglob("*")):
        if not path.is_file():
            continue
        data = path.read_bytes()
        files.append(
            {
                "path": str(path.relative_to(root)),
                "sha256": hashlib.sha256(data).hexdigest(),
                "size": len(data),
            }
        )
    manifest = {
        "schema_version": "1",
        "type": "skill_bundle",
        "name": "calendar-helper",
        "version": version,
        "created_at": "2026-03-10T00:00:00+00:00",
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


def _write_signed_behavior_pack(
    root: Path,
    *,
    key_path: Path,
    version: str,
    tone: str,
    custom_text: str,
) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "instructions.yaml").write_text(
        yaml.safe_dump(
            {
                "tone": tone,
                "custom_persona_text": custom_text,
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    files: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.name in {"manifest.json", "manifest.json.sig"}:
            continue
        data = path.read_bytes()
        files.append(
            {
                "path": str(path.relative_to(root)),
                "sha256": hashlib.sha256(data).hexdigest(),
                "size": len(data),
            }
        )
    manifest = {
        "schema_version": "1",
        "type": "behavior_pack",
        "name": "operator-tone",
        "version": version,
        "created_at": "2026-03-10T00:00:00+00:00",
        "files": files,
        "declared_capabilities": {
            "network": [],
            "filesystem": [],
            "shell": [],
            "environment": [],
            "tools": [],
        },
        "provenance": {
            "source_repo": "https://github.com/trusted-dev/behavior-pack",
            "builder_id": "pytest",
        },
    }
    manifest_path = root / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    _sign_manifest(manifest_path, key_path=key_path)
    return root


@pytest.mark.asyncio
async def test_behavioral_due_reminder_executes_without_confirmation_or_lockdown(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _successful_send(
        self: ChannelDeliveryService,
        *,
        target: DeliveryTarget,
        message: str,
    ) -> DeliveryResult:
        _ = (self, message)
        return DeliveryResult(attempted=True, sent=True, reason="sent", target=target)

    monkeypatch.setattr(ChannelDeliveryService, "send", _successful_send)
    daemon_task, client, _config = await _start_daemon(tmp_path)
    try:
        created = await client.call(
            "task.create",
            {
                "name": "allowed-reminder",
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
            predicate=lambda event: (
                str(event.get("data", {}).get("tool_name", "")) == "message.send"
                and bool(event.get("data", {}).get("success")) is True
            ),
        )

        pending = await client.call("task.pending_confirmations", {"task_id": created["id"]})
        sessions = await client.call("session.list")
        session_row = next(item for item in sessions["sessions"] if item["id"] == background_sid)

        assert session_row["lockdown_level"] == "normal"
        assert pending["count"] == 0
    finally:
        await _shutdown_daemon(daemon_task, client)


@pytest.mark.asyncio
async def test_behavioral_out_of_scope_background_action_routes_to_confirmation(
    tmp_path: Path,
) -> None:
    daemon_task, client, _config = await _start_daemon(tmp_path)
    try:
        created = await client.call(
            "task.create",
            {
                "name": "scoped-reminder",
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

        background_sid = await _wait_for_task_session_id(client, task_id=str(created["id"]))
        pending = await _wait_for_task_pending_confirmation(client, task_id=str(created["id"]))
        queued = pending["pending"][0]
        confirmation_id = str(queued.get("confirmation_id", ""))

        action_pending = await client.call("action.pending", {"status": "pending", "limit": 20})
        pending_action = next(
            item
            for item in action_pending["actions"]
            if str(item.get("confirmation_id", "")) == confirmation_id
        )
        sessions = await client.call("session.list")
        executed = await client.call(
            "audit.query",
            {"event_type": "ToolExecuted", "session_id": background_sid, "limit": 20},
        )

        session_row = next(item for item in sessions["sessions"] if item["id"] == background_sid)

        assert session_row["lockdown_level"] == "normal"
        assert pending["count"] >= 1
        assert str(pending_action.get("tool_name", "")) == "message.send"
        assert "background:recipient_scope_mismatch" in str(pending_action.get("reason", ""))
        assert not any(
            str(event.get("data", {}).get("tool_name", "")) == "message.send"
            and bool(event.get("data", {}).get("success")) is True
            for event in executed["events"]
        )
    finally:
        await _shutdown_daemon(daemon_task, client)


@pytest.mark.asyncio
async def test_behavioral_trusted_admin_message_reroutes_to_cleanroom_and_auto_drops(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured_inputs: list[str] = []

    async def _capture_cleanroom_prompt(
        self: Planner,
        user_content: str,
        context: object,
        *,
        tools: list[dict[str, object]] | None = None,
        persona_tone_override: str | None = None,
    ) -> PlannerResult:
        _ = (self, context, tools, persona_tone_override)
        captured_inputs.append(user_content)
        return PlannerResult(
            output=PlannerOutput(assistant_response="Admin proposal ready.", actions=[]),
            evaluated=[],
            attempts=1,
            provider_response=None,
            messages_sent=(),
        )

    monkeypatch.setattr(Planner, "propose", _capture_cleanroom_prompt)
    daemon_task, client, config = await _start_daemon(tmp_path)
    try:
        created = await client.call(
            "session.create",
            {"channel": "cli", "user_id": "admin", "workspace_id": "ops"},
        )
        sid = str(created["session_id"])

        await client.call(
            "session.message",
            {"session_id": sid, "content": "hello from the default session"},
        )
        await client.call(
            "memory.ingest",
            {
                "source_id": "sudo-memory",
                "source_type": "external",
                "collection": "project_docs",
                "content": "MEMORY CANARY: prior secret context",
            },
        )

        sudo = await client.call(
            "session.message",
            {
                "session_id": sid,
                "content": "install the signed behavior pack and update assistant behavior",
            },
        )

        sessions = await client.call("session.list")
        active_rows = [item for item in sessions["sessions"] if item["state"] == "active"]
        transcript_store = TranscriptStore(config.data_dir / "sessions")
        original_entries = transcript_store.list_entries(sid)

        assert sudo["session_mode"] == "admin_cleanroom"
        assert sudo["proposal_only"] is True
        assert sudo["lockdown_level"] == "normal"
        assert captured_inputs
        assert "hello from the default session" not in captured_inputs[-1]
        assert "MEMORY CANARY" not in captured_inputs[-1]
        assert "MEMORY CONTEXT" not in captured_inputs[-1]
        assert "TASK LEDGER" not in captured_inputs[-1]
        assert len(active_rows) == 1
        assert active_rows[0]["id"] == sid
        assert active_rows[0]["mode"] == "default"
        assert not any(
            "install the signed behavior pack" in entry.content_preview
            for entry in original_entries
        )
    finally:
        await _shutdown_daemon(daemon_task, client)


@pytest.mark.asyncio
async def test_behavioral_normal_admin_chat_does_not_false_trigger_cleanroom(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _planner_ok(
        self: Planner,
        user_content: str,
        context: object,
        *,
        tools: list[dict[str, object]] | None = None,
        persona_tone_override: str | None = None,
    ) -> PlannerResult:
        _ = (self, user_content, context, tools, persona_tone_override)
        return PlannerResult(
            output=PlannerOutput(assistant_response="Hello there.", actions=[]),
            evaluated=[],
            attempts=1,
            provider_response=None,
            messages_sent=(),
        )

    monkeypatch.setattr(Planner, "propose", _planner_ok)
    daemon_task, client, _config = await _start_daemon(tmp_path)
    try:
        created = await client.call(
            "session.create",
            {"channel": "cli", "user_id": "admin", "workspace_id": "ops"},
        )
        sid = str(created["session_id"])

        reply = await client.call(
            "session.message",
            {"session_id": sid, "content": "hello there"},
        )

        assert reply["session_id"] == sid
        assert reply["session_mode"] == "default"
        assert reply["proposal_only"] is False
        assert reply["lockdown_level"] == "normal"
    finally:
        await _shutdown_daemon(daemon_task, client)


@pytest.mark.asyncio
async def test_behavioral_signed_skill_apply_hot_reloads_tool_without_restart(
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

    daemon_task, client, _config = await _start_daemon(
        tmp_path,
        allowed_signers_path=allowed_signers,
    )
    try:
        proposal = await client.call(
            "admin.selfmod.propose",
            {"artifact_path": str(artifact)},
        )
        preview = await client.call(
            "admin.selfmod.apply",
            {"proposal_id": proposal["proposal_id"]},
        )
        applied = await client.call(
            "admin.selfmod.apply",
            {"proposal_id": proposal["proposal_id"], "confirm": True},
        )
        change_id = str(applied["change_id"])

        status_after_apply = await client.call("daemon.status")
        created = await client.call("session.create", {"channel": "cli"})
        captured_before_apply_message = len(captured_tools)
        await client.call(
            "session.message",
            {"session_id": created["session_id"], "content": "hello"},
        )
        apply_message_toolsets = captured_tools[captured_before_apply_message:]

        rollback = await client.call(
            "admin.selfmod.rollback",
            {"change_id": change_id},
        )
        status_after_rollback = await client.call("daemon.status")
        captured_before_rollback_message = len(captured_tools)
        await client.call(
            "session.message",
            {"session_id": created["session_id"], "content": "hello again"},
        )
        rollback_message_toolsets = captured_tools[captured_before_rollback_message:]

        assert proposal["valid"] is True
        assert preview["applied"] is False
        assert preview["requires_confirmation"] is True
        assert applied["applied"] is True
        assert change_id
        assert "skill.calendar-helper.lookup" in status_after_apply["tools_registered"]
        assert apply_message_toolsets
        assert any(
            item.get("function", {}).get("name") == "skill_calendar_helper_lookup"
            for toolset in apply_message_toolsets
            for item in toolset
        )
        assert rollback["rolled_back"] is True
        assert "skill.calendar-helper.lookup" not in status_after_rollback["tools_registered"]
        assert rollback_message_toolsets
        assert not any(
            item.get("function", {}).get("name") == "skill_calendar_helper_lookup"
            for toolset in rollback_message_toolsets
            for item in toolset
        )
    finally:
        await _shutdown_daemon(daemon_task, client)


@pytest.mark.asyncio
async def test_behavioral_integrity_mismatch_blocks_apply_and_keeps_last_known_good(
    tmp_path: Path,
) -> None:
    key_path = _generate_ssh_keypair(tmp_path, name="dev-key")
    allowed_signers = tmp_path / "allowed_signers"
    _write_allowed_signers(
        allowed_signers,
        principal="dev",
        public_key=Path(f"{key_path}.pub"),
    )

    daemon_task, client, _config = await _start_daemon(
        tmp_path,
        allowed_signers_path=allowed_signers,
    )
    try:
        stable = _write_signed_behavior_pack(
            tmp_path / "behavior-pack-v1",
            key_path=key_path,
            version="1.0.0",
            tone="friendly",
            custom_text="Stay warm.",
        )
        stable_proposal = await client.call(
            "admin.selfmod.propose",
            {"artifact_path": str(stable)},
        )
        stable_apply = await client.call(
            "admin.selfmod.apply",
            {"proposal_id": stable_proposal["proposal_id"], "confirm": True},
        )

        candidate = _write_signed_behavior_pack(
            tmp_path / "behavior-pack-v2",
            key_path=key_path,
            version="1.0.1",
            tone="strict",
            custom_text="Stay strict.",
        )
        candidate_proposal = await client.call(
            "admin.selfmod.propose",
            {"artifact_path": str(candidate)},
        )
        (candidate / "instructions.yaml").write_text(
            yaml.safe_dump(
                {
                    "tone": "strict",
                    "custom_persona_text": "tampered payload",
                },
                sort_keys=False,
            ),
            encoding="utf-8",
        )

        result = await client.call(
            "admin.selfmod.apply",
            {"proposal_id": candidate_proposal["proposal_id"], "confirm": True},
        )
        status = await client.call("daemon.status")
        operator_tone = status["selfmod"]["behavior_packs"]["operator-tone"]

        assert stable_apply["applied"] is True
        assert result["applied"] is False
        assert result["reason"] == "integrity_mismatch"
        assert result["active_version"] == "1.0.0"
        assert operator_tone["enabled"] is True
        assert operator_tone["active_version"] == "1.0.0"
        assert status["selfmod"]["incident"]["reason"] == "integrity_mismatch"
    finally:
        await _shutdown_daemon(daemon_task, client)


@pytest.mark.asyncio
async def test_behavioral_task_handoff_returns_summary_and_artifact_refs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _task_only_planner(
        self: Planner,
        user_content: str,
        context: object,
        *,
        tools: list[dict[str, object]] | None = None,
        persona_tone_override: str | None = None,
    ) -> PlannerResult:
        _ = (self, context, tools, persona_tone_override)
        if "TASK REQUEST:" in user_content:
            return PlannerResult(
                output=PlannerOutput(
                    assistant_response=(
                        "Reviewed README.md and prepared a patch. RAW DIFF stays in the task log."
                    ),
                    actions=[],
                ),
                evaluated=[],
                attempts=1,
                provider_response=None,
                messages_sent=(),
            )
        return PlannerResult(
            output=PlannerOutput(assistant_response="ok", actions=[]),
            evaluated=[],
            attempts=1,
            provider_response=None,
            messages_sent=(),
        )

    monkeypatch.setattr(Planner, "propose", _task_only_planner)
    policy_text = (
        'version: "1"\n'
        "default_require_confirmation: false\n"
        "default_capabilities:\n"
        "  - file.read\n"
    )
    daemon_task, client, _config = await _start_daemon(tmp_path, policy_text=policy_text)
    try:
        created = await client.call("session.create", {"channel": "cli"})
        sid = str(created["session_id"])
        result = await client.call(
            "session.message",
            {
                "session_id": sid,
                "content": "delegate this review task",
                "task": {
                    "enabled": True,
                    "task_description": "Review README.md and summarize the outcome.",
                    "file_refs": ["README.md"],
                    "capabilities": ["file.read"],
                },
            },
        )

        task_result = dict(result.get("task_result") or {})
        assert result["session_id"] == sid
        assert task_result["success"] is True
        assert task_result["handoff_mode"] == "summary_only"
        assert task_result["raw_log_ref"]
        assert task_result["task_session_id"]
        assert "RAW DIFF stays in the task log." in result["response"]
        assert "task log" in task_result["summary"]
    finally:
        await _shutdown_daemon(daemon_task, client)


@pytest.mark.asyncio
async def test_behavioral_task_session_excludes_command_transcript_and_memory_from_prompt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured_inputs: list[str] = []

    async def _capture_task_prompt(
        self: Planner,
        user_content: str,
        context: object,
        *,
        tools: list[dict[str, object]] | None = None,
        persona_tone_override: str | None = None,
    ) -> PlannerResult:
        _ = (self, context, tools, persona_tone_override)
        captured_inputs.append(user_content)
        return PlannerResult(
            output=PlannerOutput(assistant_response="Task summary ready.", actions=[]),
            evaluated=[],
            attempts=1,
            provider_response=None,
            messages_sent=(),
        )

    monkeypatch.setattr(Planner, "propose", _capture_task_prompt)
    policy_text = (
        'version: "1"\n'
        "default_require_confirmation: false\n"
        "default_capabilities:\n"
        "  - memory.read\n"
        "  - file.read\n"
    )
    daemon_task, client, _config = await _start_daemon(tmp_path, policy_text=policy_text)
    try:
        created = await client.call(
            "session.create",
            {"channel": "cli", "user_id": "alice", "workspace_id": "ws1"},
        )
        sid = str(created["session_id"])

        await client.call(
            "session.message",
            {"session_id": sid, "content": "hello from command history"},
        )
        await client.call(
            "memory.ingest",
            {
                "source_id": "task-canary",
                "source_type": "external",
                "collection": "project_docs",
                "content": "MEMORY CANARY: delegated tasks must not see this",
            },
        )

        await client.call(
            "session.message",
            {
                "session_id": sid,
                "content": "run an isolated task",
                "task": {
                    "enabled": True,
                    "task_description": "Review README.md in isolation.",
                    "file_refs": ["README.md"],
                    "capabilities": ["file.read"],
                },
            },
        )

        assert captured_inputs
        assert "hello from command history" not in captured_inputs[-1]
        assert "MEMORY CANARY" not in captured_inputs[-1]
        assert "MEMORY CONTEXT" not in captured_inputs[-1]
        assert "TASK LEDGER" not in captured_inputs[-1]
        assert "README.md" in captured_inputs[-1]
    finally:
        await _shutdown_daemon(daemon_task, client)


@pytest.mark.asyncio
async def test_behavioral_raw_task_ingest_marks_command_degraded_and_allows_fresh_cleanroom(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _planner_with_raw_task_fallback(
        self: Planner,
        user_content: str,
        context: object,
        *,
        tools: list[dict[str, object]] | None = None,
        persona_tone_override: str | None = None,
    ) -> PlannerResult:
        _ = (self, context, tools, persona_tone_override)
        if "TASK REQUEST:" in user_content:
            return PlannerResult(
                output=PlannerOutput(
                    assistant_response="RAW DIFF\n--- a/README.md\n+++ b/README.md\n+secret",
                    actions=[],
                ),
                evaluated=[],
                attempts=1,
                provider_response=None,
                messages_sent=(),
            )
        return PlannerResult(
            output=PlannerOutput(assistant_response="Admin proposal ready.", actions=[]),
            evaluated=[],
            attempts=1,
            provider_response=None,
            messages_sent=(),
        )

    monkeypatch.setattr(Planner, "propose", _planner_with_raw_task_fallback)
    policy_text = (
        'version: "1"\n'
        "default_require_confirmation: false\n"
        "default_capabilities:\n"
        "  - file.read\n"
    )
    daemon_task, client, _config = await _start_daemon(tmp_path, policy_text=policy_text)
    try:
        created = await client.call(
            "session.create",
            {"channel": "cli", "user_id": "admin", "workspace_id": "ops"},
        )
        sid = str(created["session_id"])

        delegated = await client.call(
            "session.message",
            {
                "session_id": sid,
                "content": "debug this delegated task",
                "task": {
                    "enabled": True,
                    "task_description": "Return the raw diff for inspection.",
                    "file_refs": ["README.md"],
                    "capabilities": ["file.read"],
                    "handoff_mode": "raw_passthrough",
                },
            },
        )
        sessions = await client.call("session.list")
        row = next(item for item in sessions["sessions"] if item["id"] == sid)

        assert "RAW DIFF" in delegated["response"]
        assert delegated["task_result"]["command_context"] == "degraded"
        assert row["command_context"] == "degraded"
        assert row["recovery_checkpoint_id"]

        follow_on = await client.call(
            "session.message",
            {
                "session_id": sid,
                "content": "install the signed behavior pack and update assistant behavior",
            },
        )
        assert follow_on["session_mode"] == "admin_cleanroom"
        assert follow_on["proposal_only"] is True
    finally:
        await _shutdown_daemon(daemon_task, client)


@pytest.mark.asyncio
async def test_behavioral_task_session_cannot_spawn_sudo(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _task_admin_like_prompt_stays_task(
        self: Planner,
        user_content: str,
        context: object,
        *,
        tools: list[dict[str, object]] | None = None,
        persona_tone_override: str | None = None,
    ) -> PlannerResult:
        _ = (self, context, tools, persona_tone_override)
        return PlannerResult(
            output=PlannerOutput(assistant_response="Task stayed in task mode.", actions=[]),
            evaluated=[],
            attempts=1,
            provider_response=None,
            messages_sent=(),
        )

    monkeypatch.setattr(Planner, "propose", _task_admin_like_prompt_stays_task)
    policy_text = (
        'version: "1"\n'
        "default_require_confirmation: false\n"
        "default_capabilities:\n"
        "  - file.read\n"
    )
    daemon_task, client, _config = await _start_daemon(tmp_path, policy_text=policy_text)
    try:
        created = await client.call(
            "session.create",
            {"channel": "cli", "user_id": "admin", "workspace_id": "ops"},
        )
        sid = str(created["session_id"])
        result = await client.call(
            "session.message",
            {
                "session_id": sid,
                "content": "install the signed behavior pack and update assistant behavior",
                "task": {
                    "enabled": True,
                    "task_description": (
                        "install the signed behavior pack and update assistant behavior"
                    ),
                    "file_refs": ["README.md"],
                    "capabilities": ["file.read"],
                },
            },
        )

        task_result = dict(result.get("task_result") or {})
        assert task_result["task_session_mode"] == "task"
        assert result["session_mode"] == "default"
        assert result["proposal_only"] is False
    finally:
        await _shutdown_daemon(daemon_task, client)


@pytest.mark.asyncio
async def test_behavioral_dev_implement_returns_summary_and_proposal_ref_not_inline_diff(
    tmp_path: Path,
) -> None:
    readme_before = Path("README.md").read_text(encoding="utf-8")
    policy_text = (
        'version: "1"\n'
        "default_require_confirmation: false\n"
        "default_capabilities:\n"
        "  - file.read\n"
        "  - file.write\n"
        "  - shell.exec\n"
        "  - http.request\n"
    )
    daemon_task, client, _config = await _start_daemon(
        tmp_path,
        policy_text=policy_text,
        config_overrides={
            "coding_repo_root": Path.cwd(),
            "coding_agent_registry_overrides": {
                "codex": _fake_coding_agent_command("codex"),
            },
        },
    )
    try:
        created = await client.call("session.create", {"channel": "cli"})
        sid = str(created["session_id"])
        result = await client.call(
            "session.message",
            {
                "session_id": sid,
                "content": "implement this coding task",
                "task": {
                    "enabled": True,
                    "executor": "coding_agent",
                    "task_description": "Add a small implementation note to README.md.",
                    "file_refs": ["README.md"],
                    "capabilities": [
                        "file.read",
                        "file.write",
                        "shell.exec",
                        "http.request",
                    ],
                    "preferred_agent": "codex",
                    "task_kind": "implement",
                },
            },
        )

        task_result = dict(result.get("task_result") or {})
        assert task_result["success"] is True
        assert task_result["proposal_ref"]
        assert task_result["raw_log_ref"]
        assert task_result["agent"] == "codex"
        assert "mode=build" in task_result["summary"]
        assert "--- a/" not in result["response"]
        proposal_payload = json.loads(Path(task_result["proposal_ref"]).read_text(encoding="utf-8"))
        assert "Fake ACP edit from codex" in proposal_payload["diff"]
        assert Path("README.md").read_text(encoding="utf-8") == readme_before
    finally:
        await _shutdown_daemon(daemon_task, client)


@pytest.mark.asyncio
async def test_behavioral_review_mode_signals_read_only_and_preserves_opportunistic_proposals(
    tmp_path: Path,
) -> None:
    policy_text = (
        'version: "1"\n'
        "default_require_confirmation: false\n"
        "default_capabilities:\n"
        "  - file.read\n"
        "  - file.write\n"
        "  - shell.exec\n"
        "  - http.request\n"
    )
    daemon_task, client, _config = await _start_daemon(
        tmp_path,
        policy_text=policy_text,
        config_overrides={
            "coding_repo_root": Path.cwd(),
            "coding_agent_registry_overrides": {
                "claude": _fake_coding_agent_command("claude"),
            },
        },
    )
    try:
        created = await client.call("session.create", {"channel": "cli"})
        sid = str(created["session_id"])
        result = await client.call(
            "session.message",
            {
                "session_id": sid,
                "content": "review this coding task",
                "task": {
                    "enabled": True,
                    "executor": "coding_agent",
                    "task_description": (
                        "Review README.md for issues. OPPORTUNISTIC_EDIT if needed."
                    ),
                    "file_refs": ["README.md"],
                    "capabilities": [
                        "file.read",
                        "file.write",
                        "shell.exec",
                        "http.request",
                    ],
                    "preferred_agent": "claude",
                    "task_kind": "review",
                },
            },
        )

        task_result = dict(result.get("task_result") or {})
        assert task_result["success"] is True
        assert task_result["proposal_ref"]
        assert task_result["agent"] == "claude"
        assert "mode=plan" in task_result["summary"]
        proposal_payload = json.loads(Path(task_result["proposal_ref"]).read_text(encoding="utf-8"))
        assert "Fake ACP edit from claude" in proposal_payload["diff"]
    finally:
        await _shutdown_daemon(daemon_task, client)


@pytest.mark.asyncio
async def test_behavioral_unavailable_agent_returns_actionable_error_without_lockdown(
    tmp_path: Path,
) -> None:
    policy_text = (
        'version: "1"\n'
        "default_require_confirmation: false\n"
        "default_capabilities:\n"
        "  - file.read\n"
        "  - file.write\n"
        "  - shell.exec\n"
    )
    daemon_task, client, _config = await _start_daemon(
        tmp_path,
        policy_text=policy_text,
        config_overrides={
            "coding_repo_root": Path.cwd(),
            "coding_agent_registry_overrides": {
                "codex": "definitely-missing-acp-adapter",
            },
        },
    )
    try:
        created = await client.call("session.create", {"channel": "cli"})
        sid = str(created["session_id"])
        result = await client.call(
            "session.message",
            {
                "session_id": sid,
                "content": "try the unavailable coding agent",
                "task": {
                    "enabled": True,
                    "executor": "coding_agent",
                    "task_description": "Attempt a coding task.",
                    "file_refs": ["README.md"],
                    "capabilities": ["file.read", "file.write", "shell.exec"],
                    "preferred_agent": "codex",
                    "task_kind": "implement",
                },
            },
        )

        task_result = dict(result.get("task_result") or {})
        assert task_result["success"] is False
        assert task_result["reason"] == "agent_unavailable"
        assert "not available" in task_result["summary"].lower()
        assert result["lockdown_level"] in {"off", "none", "", "normal"}
    finally:
        await _shutdown_daemon(daemon_task, client)


@pytest.mark.asyncio
async def test_behavioral_coding_agent_respects_task_capability_scope(
    tmp_path: Path,
) -> None:
    readme_before = Path("README.md").read_text(encoding="utf-8")
    policy_text = (
        'version: "1"\n'
        "default_require_confirmation: false\n"
        "default_capabilities:\n"
        "  - file.read\n"
    )
    daemon_task, client, _config = await _start_daemon(
        tmp_path,
        policy_text=policy_text,
        config_overrides={
            "coding_repo_root": Path.cwd(),
            "coding_agent_registry_overrides": {
                "codex": _fake_coding_agent_command("codex"),
            },
        },
    )
    try:
        created = await client.call("session.create", {"channel": "cli"})
        sid = str(created["session_id"])
        result = await client.call(
            "session.message",
            {
                "session_id": sid,
                "content": "respect the coding-agent capability ceiling",
                "task": {
                    "enabled": True,
                    "executor": "coding_agent",
                    "task_description": "Implement a README.md change.",
                    "file_refs": ["README.md"],
                    "capabilities": ["file.read"],
                    "preferred_agent": "codex",
                    "task_kind": "implement",
                },
            },
        )

        task_result = dict(result.get("task_result") or {})
        assert task_result["success"] is False
        assert task_result["reason"] == "coding_agent_capability_denied"
        assert "missing capabilities" in task_result["summary"].lower()
        assert Path("README.md").read_text(encoding="utf-8") == readme_before
    finally:
        await _shutdown_daemon(daemon_task, client)


@pytest.mark.asyncio
async def test_behavioral_agent_fallback_chain_uses_next_available_agent(
    tmp_path: Path,
) -> None:
    policy_text = (
        'version: "1"\n'
        "default_require_confirmation: false\n"
        "default_capabilities:\n"
        "  - file.read\n"
        "  - file.write\n"
        "  - shell.exec\n"
        "  - http.request\n"
    )
    daemon_task, client, _config = await _start_daemon(
        tmp_path,
        policy_text=policy_text,
        config_overrides={
            "coding_repo_root": Path.cwd(),
            "coding_agent_registry_overrides": {
                "codex": "definitely-missing-acp-adapter",
                "claude": _fake_coding_agent_command("claude"),
            },
        },
    )
    try:
        created = await client.call("session.create", {"channel": "cli"})
        sid = str(created["session_id"])
        result = await client.call(
            "session.message",
            {
                "session_id": sid,
                "content": "fallback to the next coding agent",
                "task": {
                    "enabled": True,
                    "executor": "coding_agent",
                    "task_description": "Implement a tiny README.md tweak.",
                    "file_refs": ["README.md"],
                    "capabilities": [
                        "file.read",
                        "file.write",
                        "shell.exec",
                        "http.request",
                    ],
                    "preferred_agent": "codex",
                    "fallback_agents": ["claude"],
                    "task_kind": "implement",
                },
            },
        )

        task_result = dict(result.get("task_result") or {})
        assert task_result["success"] is True
        assert task_result["agent"] == "claude"
        selected = await _wait_for_audit_event(
            client,
            event_type="CodingAgentSelected",
            predicate=lambda item: str(item.get("data", {}).get("selected_agent", "")) == "claude",
            session_id=str(task_result["task_session_id"]),
        )
        assert selected["data"]["fallback_used"] is True
    finally:
        await _shutdown_daemon(daemon_task, client)
