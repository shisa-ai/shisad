"""v0.4 behavioral extensions for background execution and admin self-modification."""

from __future__ import annotations

import asyncio
import hashlib
import json
import socket
import subprocess
import sys
import urllib.error
import urllib.request
from collections.abc import Callable
from contextlib import suppress
from pathlib import Path
from typing import Any

import pytest
import yaml

from shisad.approver.main import ApproverService
from shisad.channels.base import DeliveryTarget
from shisad.channels.delivery import ChannelDeliveryService, DeliveryResult
from shisad.core.api.transport import ControlClient
from shisad.core.approval import generate_totp_code
from shisad.core.config import DaemonConfig
from shisad.core.planner import (
    ActionProposal,
    EvaluatedProposal,
    Planner,
    PlannerOutput,
    PlannerResult,
)
from shisad.core.transcript import TranscriptStore
from shisad.core.types import ToolName
from shisad.daemon.runner import run_daemon
from tests.helpers.daemon import wait_for_socket as _wait_for_socket
from tests.helpers.mcp import write_mock_mcp_server
from tests.helpers.signer import StubSignerService, generate_ed25519_private_key, public_key_pem
from tests.helpers.webauthn import make_authentication_payload, make_registration_payload

REPO_ROOT = Path(__file__).resolve().parents[2]
README_PATH = REPO_ROOT / "README.md"


def _base_policy() -> str:
    return 'version: "1"\ndefault_require_confirmation: false\n'


def _reserve_local_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _approval_json_url(url: str) -> str:
    separator = "&" if "?" in url else "?"
    return f"{url}{separator}format=json"


def _http_get_json(url: str) -> tuple[int, dict[str, Any]]:
    request = urllib.request.Request(_approval_json_url(url), method="GET")
    try:
        with urllib.request.urlopen(request, timeout=5.0) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8")
        return exc.code, json.loads(body) if body else {}


def _http_post_json(url: str, payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=5.0) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8")
        return exc.code, json.loads(body) if body else {}


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
    await asyncio.wait_for(daemon_task, timeout=5)


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
    raise AssertionError(f"Timed out waiting for pending confirmation for task {task_id}: {latest}")


def _fake_coding_agent_command(agent_name: str) -> str:
    script = Path(__file__).resolve().parents[1] / "fixtures" / "fake_acp_agent.py"
    return f"{sys.executable} {script} --agent-name {agent_name}"


def _complete_close_gate_result() -> PlannerResult:
    return PlannerResult(
        output=PlannerOutput(
            assistant_response=(
                "SELF_CHECK_STATUS: COMPLETE\n"
                "SELF_CHECK_REASON: complete\n"
                "SELF_CHECK_NOTES: The task output completed the delegated request."
            ),
            actions=[],
        ),
        evaluated=[],
        attempts=1,
        provider_response=None,
        messages_sent=(),
    )


@pytest.fixture(autouse=True)
def _default_complete_task_close_gate(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _planner(
        self: Planner,
        user_content: str,
        context: object,
        *,
        tools: list[dict[str, object]] | None = None,
        persona_tone_override: str | None = None,
    ) -> PlannerResult:
        _ = (self, user_content, context, tools, persona_tone_override)
        return _complete_close_gate_result()

    monkeypatch.setattr(Planner, "propose", _planner)


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
                        "parameters": [{"name": "query", "type": "string", "required": True}],
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
async def test_behavioral_tool_execute_confirmation_surfaces_approval_protocol_metadata(
    tmp_path: Path,
) -> None:
    policy_text = "\n".join(
        [
            'version: "1"',
            "default_require_confirmation: false",
            "default_capabilities:",
            "  - file.read",
            "  - memory.read",
            "tools:",
            "  shell.exec:",
            "    capabilities_required:",
            "      - shell.exec",
        ]
    )
    daemon_task, client, _config = await _start_daemon(
        tmp_path,
        policy_text=policy_text + "\n",
        config_overrides={"assistant_fs_roots": [REPO_ROOT]},
    )
    try:
        created = await client.call(
            "session.create",
            {"channel": "cli", "user_id": "alice", "workspace_id": "ws1"},
        )
        sid = str(created["session_id"])

        proposed = await client.call(
            "tool.execute",
            {
                "session_id": sid,
                "tool_name": "shell.exec",
                "command": [sys.executable, "-c", "print('behavioral-a0')"],
                "limits": {"timeout_seconds": 5, "output_bytes": 2048},
                "degraded_mode": "fail_open",
                "security_critical": False,
            },
        )
        assert proposed["allowed"] is False
        assert proposed["confirmation_required"] is True
        confirmation_id = str(proposed["confirmation_id"])

        pending = await client.call("action.pending", {"confirmation_id": confirmation_id})
        actions = list(pending.get("actions", []))
        assert len(actions) == 1
        action = actions[0]
        assert action["required_level"] == "software"
        assert action["selected_backend_id"] == "software.default"
        assert action["approval_envelope"]["schema_version"] == "shisad.approval.v1"
        assert str(action["approval_envelope"]["action_digest"]).startswith("sha256:")
        assert str(action["approval_envelope_hash"]).startswith("sha256:")

        confirmed = await client.call(
            "action.confirm",
            {
                "confirmation_id": confirmation_id,
                "decision_nonce": str(action["decision_nonce"]),
                "reason": "behavioral_a0",
            },
        )
        assert confirmed["confirmed"] is True
        assert confirmed["status"] == "approved"
        assert confirmed["approval_level"] == "software"
        assert confirmed["approval_method"] == "software"

        approved = await _wait_for_audit_event(
            client,
            event_type="ToolApproved",
            session_id=sid,
            predicate=lambda event: (
                str(event.get("data", {}).get("tool_name", "")) == "shell.exec"
                and str(event.get("data", {}).get("approval_level", "")) == "software"
                and str(event.get("data", {}).get("approval_method", "")) == "software"
                and str(event.get("data", {}).get("approval_evidence_hash", "")).startswith(
                    "sha256:"
                )
            ),
        )
        executed = await _wait_for_audit_event(
            client,
            event_type="ToolExecuted",
            session_id=sid,
            predicate=lambda event: (
                str(event.get("data", {}).get("tool_name", "")) == "shell.exec"
                and bool(event.get("data", {}).get("success")) is True
                and str(event.get("data", {}).get("approval_level", "")) == "software"
                and str(event.get("data", {}).get("approval_method", "")) == "software"
                and str(event.get("data", {}).get("approval_evidence_hash", "")).startswith(
                    "sha256:"
                )
            ),
        )
        assert approved["event_type"] == "ToolApproved"
        assert executed["event_type"] == "ToolExecuted"
    finally:
        await _shutdown_daemon(daemon_task, client)


@pytest.mark.asyncio
async def test_behavioral_mcp_stdio_tool_execute_requires_confirmation_then_executes(
    tmp_path: Path,
) -> None:
    server_script = write_mock_mcp_server(tmp_path / "mock_mcp_server.py")
    daemon_task, client, _config = await _start_daemon(
        tmp_path,
        config_overrides={
            "mcp_servers": [
                {
                    "name": "docs",
                    "transport": "stdio",
                    "command": [sys.executable, str(server_script)],
                    "timeout_seconds": 10.0,
                }
            ]
        },
    )
    try:
        created = await client.call(
            "session.create",
            {"channel": "cli", "user_id": "alice", "workspace_id": "ws1"},
        )
        sid = str(created["session_id"])

        result = await client.call(
            "tool.execute",
            {
                "session_id": sid,
                "tool_name": "mcp.docs.lookup-doc",
                "command": ["mcp"],
                "arguments": {"query": "roadmap", "limit": 4},
                "security_critical": False,
                "degraded_mode": "fail_open",
            },
        )

        assert result["allowed"] is False
        assert result["confirmation_required"] is True
        confirmation_id = str(result["confirmation_id"])

        pending = await client.call("action.pending", {"confirmation_id": confirmation_id})
        actions = list(pending.get("actions", []))
        assert len(actions) == 1
        action = actions[0]

        confirmed = await client.call(
            "action.confirm",
            {
                "confirmation_id": confirmation_id,
                "decision_nonce": str(action["decision_nonce"]),
                "reason": "behavioral_mcp_i1",
            },
        )
        assert confirmed["confirmed"] is True
        assert confirmed["status"] == "approved"

        approved = await _wait_for_audit_event(
            client,
            event_type="ToolApproved",
            session_id=sid,
            predicate=lambda event: (
                str(event.get("data", {}).get("tool_name", "")) == "mcp.docs.lookup-doc"
                and str(event.get("data", {}).get("approval_level", "")) == "software"
                and str(event.get("data", {}).get("approval_method", "")) == "software"
            ),
        )

        executed = await _wait_for_audit_event(
            client,
            event_type="ToolExecuted",
            session_id=sid,
            predicate=lambda event: (
                str(event.get("data", {}).get("tool_name", "")) == "mcp.docs.lookup-doc"
                and bool(event.get("data", {}).get("success")) is True
                and str(event.get("data", {}).get("approval_level", "")) == "software"
                and str(event.get("data", {}).get("approval_method", "")) == "software"
            ),
        )
        assert approved["event_type"] == "ToolApproved"
        assert str(executed.get("data", {}).get("actor", "")) == "tool_runtime"
    finally:
        await _shutdown_daemon(daemon_task, client)


@pytest.mark.asyncio
async def test_behavioral_mcp_stdio_tool_execute_rejects_invalid_arguments_before_upstream_call(
    tmp_path: Path,
) -> None:
    server_script = write_mock_mcp_server(tmp_path / "mock_mcp_server.py")
    daemon_task, client, _config = await _start_daemon(
        tmp_path,
        config_overrides={
            "mcp_servers": [
                {
                    "name": "docs",
                    "transport": "stdio",
                    "command": [sys.executable, str(server_script)],
                    "timeout_seconds": 10.0,
                }
            ]
        },
    )
    try:
        created = await client.call(
            "session.create",
            {"channel": "cli", "user_id": "alice", "workspace_id": "ws1"},
        )
        sid = str(created["session_id"])

        with pytest.raises(RuntimeError, match=r"RPC error -32602"):
            await client.call(
                "tool.execute",
                {
                    "session_id": sid,
                    "tool_name": "mcp.docs.lookup-doc",
                    "command": ["mcp"],
                    "arguments": {"query": "roadmap", "limit": True},
                    "security_critical": False,
                    "degraded_mode": "fail_open",
                },
            )

        rejected = await _wait_for_audit_event(
            client,
            event_type="ToolRejected",
            session_id=sid,
            predicate=lambda event: (
                str(event.get("data", {}).get("tool_name", "")) == "mcp.docs.lookup-doc"
                and str(event.get("data", {}).get("reason", "")).startswith(
                    "invalid_tool_arguments:schema validation failed: "
                    "Argument 'limit': expected type 'integer', got 'bool'"
                )
            ),
        )
        assert rejected["event_type"] == "ToolRejected"
    finally:
        await _shutdown_daemon(daemon_task, client)


@pytest.mark.asyncio
async def test_behavioral_totp_confirmation_executes_and_records_l1_audit(
    tmp_path: Path,
) -> None:
    policy_text = "\n".join(
        [
            'version: "1"',
            "default_require_confirmation: false",
            "default_capabilities:",
            "  - shell.exec",
            "tools:",
            "  shell.exec:",
            "    capabilities_required:",
            "      - shell.exec",
            "    confirmation:",
            "      level: reauthenticated",
            "      methods:",
            "        - totp",
        ]
    )
    daemon_task, client, _config = await _start_daemon(
        tmp_path,
        policy_text=policy_text + "\n",
        config_overrides={"assistant_fs_roots": [REPO_ROOT]},
    )
    try:
        started = await client.call(
            "2fa.register_begin",
            {"method": "totp", "user_id": "alice", "name": "ops-laptop"},
        )
        confirmed_factor = await client.call(
            "2fa.register_confirm",
            {
                "enrollment_id": started["enrollment_id"],
                "verify_code": generate_totp_code(str(started["secret"])),
            },
        )
        assert confirmed_factor["registered"] is True

        created = await client.call(
            "session.create",
            {"channel": "cli", "user_id": "alice", "workspace_id": "ws1"},
        )
        sid = str(created["session_id"])

        proposed = await client.call(
            "tool.execute",
            {
                "session_id": sid,
                "tool_name": "shell.exec",
                "command": [sys.executable, "-c", "print('behavioral-a1')"],
                "limits": {"timeout_seconds": 5, "output_bytes": 2048},
                "degraded_mode": "fail_open",
                "security_critical": False,
            },
        )
        assert proposed["allowed"] is False
        assert proposed["confirmation_required"] is True
        confirmation_id = str(proposed["confirmation_id"])

        pending = await client.call("action.pending", {"confirmation_id": confirmation_id})
        action = pending["actions"][0]
        assert action["required_level"] == "reauthenticated"
        assert action["selected_backend_id"] == "totp.default"
        assert action["selected_backend_method"] == "totp"

        approved = await client.call(
            "action.confirm",
            {
                "confirmation_id": confirmation_id,
                "decision_nonce": str(action["decision_nonce"]),
                "approval_method": "totp",
                "proof": {"totp_code": generate_totp_code(str(started["secret"]))},
            },
        )
        assert approved["confirmed"] is True
        assert approved["status"] == "approved"
        assert approved["approval_level"] == "reauthenticated"
        assert approved["approval_method"] == "totp"

        approved_event = await _wait_for_audit_event(
            client,
            event_type="ToolApproved",
            session_id=sid,
            predicate=lambda event: (
                str(event.get("data", {}).get("tool_name", "")) == "shell.exec"
                and str(event.get("data", {}).get("approval_level", "")) == "reauthenticated"
                and str(event.get("data", {}).get("approval_method", "")) == "totp"
                and str(event.get("data", {}).get("approval_approver_principal_id", ""))
                == "ops-laptop"
            ),
        )
        executed_event = await _wait_for_audit_event(
            client,
            event_type="ToolExecuted",
            session_id=sid,
            predicate=lambda event: (
                str(event.get("data", {}).get("tool_name", "")) == "shell.exec"
                and bool(event.get("data", {}).get("success")) is True
                and str(event.get("data", {}).get("approval_level", "")) == "reauthenticated"
                and str(event.get("data", {}).get("approval_method", "")) == "totp"
            ),
        )
        assert approved_event["event_type"] == "ToolApproved"
        assert executed_event["event_type"] == "ToolExecuted"
    finally:
        await _shutdown_daemon(daemon_task, client)


@pytest.mark.asyncio
async def test_behavioral_totp_confirmation_accepts_chat_code_submission(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy_text = "\n".join(
        [
            'version: "1"',
            "default_require_confirmation: false",
            "default_capabilities:",
            "  - file.read",
            "tools:",
            "  fs.read:",
            "    capabilities_required:",
            "      - file.read",
            "    confirmation:",
            "      level: reauthenticated",
            "      methods:",
            "        - totp",
        ]
    )
    target = README_PATH

    async def _planner_fs_read(
        self: Planner,
        user_content: str,
        context: object,
        *,
        tools: list[dict[str, object]] | None = None,
        persona_tone_override: str | None = None,
    ) -> PlannerResult:
        _ = (user_content, tools, persona_tone_override)
        proposal = ActionProposal(
            action_id="u9-behavioral-chat-totp",
            tool_name=ToolName("fs.read"),
            arguments={
                "path": str(target),
                "max_bytes": 4096,
            },
            reasoning="exercise chat TOTP confirmation",
            data_sources=[],
        )
        decision = self._pep.evaluate(proposal.tool_name, proposal.arguments, context)
        return PlannerResult(
            output=PlannerOutput(
                assistant_response="pending chat totp approval",
                actions=[proposal],
            ),
            evaluated=[EvaluatedProposal(proposal=proposal, decision=decision)],
            attempts=1,
            provider_response=None,
            messages_sent=(),
        )

    monkeypatch.setattr(Planner, "propose", _planner_fs_read)
    daemon_task, client, _config = await _start_daemon(
        tmp_path,
        policy_text=policy_text + "\n",
        config_overrides={"assistant_fs_roots": [REPO_ROOT]},
    )
    try:
        started = await client.call(
            "2fa.register_begin",
            {"method": "totp", "user_id": "alice", "name": "ops-laptop"},
        )
        confirmed_factor = await client.call(
            "2fa.register_confirm",
            {
                "enrollment_id": started["enrollment_id"],
                "verify_code": generate_totp_code(str(started["secret"])),
            },
        )
        assert confirmed_factor["registered"] is True

        created = await client.call(
            "session.create",
            {"channel": "cli", "user_id": "alice", "workspace_id": "ops"},
        )
        sid = str(created["session_id"])

        proposed = await client.call(
            "session.message",
            {
                "session_id": sid,
                "channel": "cli",
                "user_id": "alice",
                "workspace_id": "ops",
                "content": "run the queued action",
            },
        )
        assert proposed["confirmation_required_actions"] >= 1
        first_response = str(proposed.get("response", "")).lower()
        assert "6-digit code" in first_response
        assert str(proposed["pending_confirmation_ids"][0]).lower() in first_response
        assert "shisad action confirm" in first_response
        assert "--totp-code 123456" in first_response

        code = generate_totp_code(str(started["secret"]))
        approved = await client.call(
            "session.message",
            {
                "session_id": sid,
                "channel": "cli",
                "user_id": "alice",
                "workspace_id": "ops",
                "content": code,
            },
        )
        assert approved["executed_actions"] == 1
        assert approved["confirmation_required_actions"] == 0
        assert code not in str(approved.get("response", ""))

        approved_event = await _wait_for_audit_event(
            client,
            event_type="ToolApproved",
            session_id=sid,
            predicate=lambda event: (
                str(event.get("data", {}).get("tool_name", "")) == "fs.read"
                and str(event.get("data", {}).get("approval_method", "")) == "totp"
                and str(event.get("data", {}).get("approval_level", "")) == "reauthenticated"
            ),
        )
        executed_event = await _wait_for_audit_event(
            client,
            event_type="ToolExecuted",
            session_id=sid,
            predicate=lambda event: (
                str(event.get("data", {}).get("tool_name", "")) == "fs.read"
                and bool(event.get("data", {}).get("success")) is True
            ),
        )
        assert approved_event["event_type"] == "ToolApproved"
        assert executed_event["event_type"] == "ToolExecuted"
    finally:
        await _shutdown_daemon(daemon_task, client)


@pytest.mark.asyncio
async def test_behavioral_webauthn_confirmation_executes_and_records_l2_audit(
    tmp_path: Path,
) -> None:
    port = _reserve_local_port()
    origin = f"http://127.0.0.1:{port}"
    policy_text = "\n".join(
        [
            'version: "1"',
            "default_require_confirmation: false",
            "default_capabilities:",
            "  - shell.exec",
            "tools:",
            "  shell.exec:",
            "    capabilities_required:",
            "      - shell.exec",
            "    confirmation:",
            "      level: bound_approval",
            "      methods:",
            "        - webauthn",
        ]
    )
    daemon_task, client, _config = await _start_daemon(
        tmp_path,
        policy_text=policy_text + "\n",
        config_overrides={
            "approval_origin": origin,
            "approval_bind_host": "127.0.0.1",
            "approval_bind_port": port,
        },
    )
    try:
        started = await client.call(
            "2fa.register_begin",
            {"method": "webauthn", "user_id": "alice", "name": "ops-phone"},
        )
        assert started["started"] is True
        register_status, register_context = await asyncio.to_thread(
            _http_get_json,
            str(started["registration_url"]),
        )
        assert register_status == 200
        assert register_context["ok"] is True
        credential, registration_payload = make_registration_payload(
            public_key_options=register_context["public_key"],
            origin=register_context["origin"],
            rp_id=register_context["rp_id"],
        )
        complete_status, registered = await asyncio.to_thread(
            _http_post_json,
            str(started["registration_url"]),
            registration_payload,
        )
        assert complete_status == 200
        assert registered["registered"] is True

        created = await client.call(
            "session.create",
            {"channel": "cli", "user_id": "alice", "workspace_id": "ws1"},
        )
        sid = str(created["session_id"])

        proposed = await client.call(
            "tool.execute",
            {
                "session_id": sid,
                "tool_name": "shell.exec",
                "command": [sys.executable, "-c", "print('behavioral-a2')"],
                "limits": {"timeout_seconds": 5, "output_bytes": 2048},
                "degraded_mode": "fail_open",
                "security_critical": False,
            },
        )
        assert proposed["allowed"] is False
        assert proposed["confirmation_required"] is True
        confirmation_id = str(proposed["confirmation_id"])

        pending = await client.call("action.pending", {"confirmation_id": confirmation_id})
        action = pending["actions"][0]
        assert action["required_level"] == "bound_approval"
        assert action["selected_backend_id"] == "webauthn.default"
        assert action["selected_backend_method"] == "webauthn"
        assert str(action["approval_url"]).startswith(f"{origin}/approve/")

        approve_status, approve_context = await asyncio.to_thread(
            _http_get_json,
            str(action["approval_url"]),
        )
        assert approve_status == 200
        assert approve_context["ok"] is True
        assertion = make_authentication_payload(
            public_key_options=approve_context["public_key"],
            credential=credential,
        )
        confirmed_status, approved = await asyncio.to_thread(
            _http_post_json,
            str(action["approval_url"]),
            assertion,
        )
        assert confirmed_status == 200
        assert approved["confirmed"] is True
        assert approved["status"] == "approved"
        assert approved["approval_level"] == "bound_approval"
        assert approved["approval_method"] == "webauthn"

        approved_event = await _wait_for_audit_event(
            client,
            event_type="ToolApproved",
            session_id=sid,
            predicate=lambda event: (
                str(event.get("data", {}).get("tool_name", "")) == "shell.exec"
                and str(event.get("data", {}).get("approval_level", "")) == "bound_approval"
                and str(event.get("data", {}).get("approval_method", "")) == "webauthn"
                and str(event.get("data", {}).get("approval_credential_id", ""))
                == registered["credential_id"]
                and str(event.get("data", {}).get("approval_review_surface", ""))
                == "browser_rendered"
            ),
        )
        executed_event = await _wait_for_audit_event(
            client,
            event_type="ToolExecuted",
            session_id=sid,
            predicate=lambda event: (
                str(event.get("data", {}).get("tool_name", "")) == "shell.exec"
                and bool(event.get("data", {}).get("success")) is True
                and str(event.get("data", {}).get("approval_level", "")) == "bound_approval"
                and str(event.get("data", {}).get("approval_method", "")) == "webauthn"
                and str(event.get("data", {}).get("approval_credential_id", ""))
                == registered["credential_id"]
            ),
        )
        assert approved_event["event_type"] == "ToolApproved"
        assert executed_event["event_type"] == "ToolExecuted"
    finally:
        await _shutdown_daemon(daemon_task, client)


@pytest.mark.asyncio
async def test_behavioral_local_fido2_helper_executes_and_records_l2_audit(
    tmp_path: Path,
) -> None:
    class _FakeDevice:
        def __init__(self) -> None:
            self._credential = None

        def register_credential(
            self,
            *,
            public_key_options: dict[str, Any],
            origin: str,
        ) -> dict[str, Any]:
            credential, payload = make_registration_payload(
                public_key_options=public_key_options,
                origin=origin,
            )
            self._credential = credential
            return payload

        def get_assertion(
            self,
            *,
            public_key_options: dict[str, Any],
            origin: str,
        ) -> dict[str, Any]:
            assert self._credential is not None
            assert origin == self._credential.origin
            return make_authentication_payload(
                public_key_options=public_key_options,
                credential=self._credential,
            )

    policy_text = "\n".join(
        [
            'version: "1"',
            "default_require_confirmation: false",
            "default_capabilities:",
            "  - shell.exec",
            "tools:",
            "  shell.exec:",
            "    capabilities_required:",
            "      - shell.exec",
            "    confirmation:",
            "      level: bound_approval",
            "      methods:",
            "        - local_fido2",
        ]
    )
    daemon_task, client, config = await _start_daemon(tmp_path, policy_text=policy_text + "\n")
    try:
        helper = ApproverService(socket_path=config.socket_path, device=_FakeDevice())
        enrolled = await helper.enroll(user_id="alice", name="ops-key")
        assert enrolled["registered"] is True
        assert enrolled["method"] == "local_fido2"

        created = await client.call(
            "session.create",
            {"channel": "cli", "user_id": "alice", "workspace_id": "ws1"},
        )
        sid = str(created["session_id"])

        proposed = await client.call(
            "tool.execute",
            {
                "session_id": sid,
                "tool_name": "shell.exec",
                "command": [sys.executable, "-c", "print('behavioral-a3')"],
                "limits": {"timeout_seconds": 5, "output_bytes": 2048},
                "degraded_mode": "fail_open",
                "security_critical": False,
            },
        )
        assert proposed["allowed"] is False
        assert proposed["confirmation_required"] is True
        confirmation_id = str(proposed["confirmation_id"])

        pending = await client.call("action.pending", {"confirmation_id": confirmation_id})
        action = pending["actions"][0]
        assert action["required_level"] == "bound_approval"
        assert action["selected_backend_id"] == "approver.local_fido2"
        assert action["selected_backend_method"] == "local_fido2"
        assert action.get("approval_url") is None
        assert action["helper_origin"]
        assert action["helper_public_key"]

        processed = await helper.process_pending_once(prompt=lambda _row: True)
        assert processed == {"processed": 1, "approved": 1, "rejected": 0}

        approved_event = await _wait_for_audit_event(
            client,
            event_type="ToolApproved",
            session_id=sid,
            predicate=lambda event: (
                str(event.get("data", {}).get("tool_name", "")) == "shell.exec"
                and str(event.get("data", {}).get("approval_level", "")) == "bound_approval"
                and str(event.get("data", {}).get("approval_method", "")) == "local_fido2"
                and str(event.get("data", {}).get("approval_credential_id", ""))
                == enrolled["credential_id"]
                and str(event.get("data", {}).get("approval_review_surface", "")) == "host_rendered"
            ),
        )
        executed_event = await _wait_for_audit_event(
            client,
            event_type="ToolExecuted",
            session_id=sid,
            predicate=lambda event: (
                str(event.get("data", {}).get("tool_name", "")) == "shell.exec"
                and bool(event.get("data", {}).get("success")) is True
                and str(event.get("data", {}).get("approval_level", "")) == "bound_approval"
                and str(event.get("data", {}).get("approval_method", "")) == "local_fido2"
                and str(event.get("data", {}).get("approval_credential_id", ""))
                == enrolled["credential_id"]
            ),
        )
        assert approved_event["event_type"] == "ToolApproved"
        assert executed_event["event_type"] == "ToolExecuted"
    finally:
        await _shutdown_daemon(daemon_task, client)


@pytest.mark.asyncio
async def test_behavioral_signed_authorization_executes_and_records_l3_audit(
    tmp_path: Path,
) -> None:
    private_key = generate_ed25519_private_key()
    with StubSignerService(private_key=private_key).run() as signer_url:
        policy_text = "\n".join(
            [
                'version: "1"',
                "default_require_confirmation: false",
                "default_capabilities:",
                "  - shell.exec",
                "tools:",
                "  shell.exec:",
                "    capabilities_required:",
                "      - shell.exec",
                "    confirmation:",
                "      level: signed_authorization",
                "      methods:",
                "        - kms",
                "      allowed_principals:",
                "        - finance-owner",
                "      allowed_credentials:",
                "        - kms:finance-primary",
                "      require_capabilities:",
                "        principal_binding: true",
                "        full_intent_signature: true",
                "        third_party_verifiable: true",
                "      fallback:",
                "        mode: deny",
                "",
            ]
        )
        daemon_task, client, _config = await _start_daemon(
            tmp_path,
            policy_text=policy_text,
            config_overrides={"signer_kms_url": signer_url},
        )
        try:
            registered = await client.call(
                "signer.register",
                {
                    "backend": "kms",
                    "user_id": "alice",
                    "key_id": "kms:finance-primary",
                    "name": "finance-owner",
                    "algorithm": "ed25519",
                    "device_type": "ledger-enterprise",
                    "public_key_pem": public_key_pem(private_key),
                },
            )
            assert registered["registered"] is True

            created = await client.call(
                "session.create",
                {"channel": "cli", "user_id": "alice", "workspace_id": "ws1"},
            )
            sid = str(created["session_id"])

            proposed = await client.call(
                "tool.execute",
                {
                    "session_id": sid,
                    "tool_name": "shell.exec",
                    "command": [sys.executable, "-c", "print('behavioral-l2')"],
                    "limits": {"timeout_seconds": 5, "output_bytes": 2048},
                    "degraded_mode": "fail_open",
                    "security_critical": False,
                },
            )
            assert proposed["allowed"] is False
            assert proposed["confirmation_required"] is True
            confirmation_id = str(proposed["confirmation_id"])

            pending = await client.call("action.pending", {"confirmation_id": confirmation_id})
            actions = list(pending.get("actions", []))
            assert len(actions) == 1
            action = actions[0]
            assert action["required_level"] == "signed_authorization"
            assert action["selected_backend_method"] == "kms"
            assert action["intent_envelope"]["schema_version"] == "shisad.intent.v1"
            assert str(action["approval_envelope"]["intent_envelope_hash"]).startswith("sha256:")

            confirmed = await client.call(
                "action.confirm",
                {
                    "confirmation_id": confirmation_id,
                    "decision_nonce": str(action["decision_nonce"]),
                    "reason": "behavioral_l2",
                },
            )
            assert confirmed["confirmed"] is True
            assert confirmed["status"] == "approved"
            assert confirmed["approval_level"] == "signed_authorization"
            assert confirmed["approval_method"] == "kms"

            approved = await _wait_for_audit_event(
                client,
                event_type="ToolApproved",
                session_id=sid,
                predicate=lambda event: (
                    str(event.get("data", {}).get("tool_name", "")) == "shell.exec"
                    and str(event.get("data", {}).get("approval_level", ""))
                    == "signed_authorization"
                    and str(event.get("data", {}).get("approval_method", "")) == "kms"
                    and str(event.get("data", {}).get("approval_signer_key_id", ""))
                    == "kms:finance-primary"
                    and str(
                        event.get("data", {}).get("approval_intent_envelope_hash", "")
                    ).startswith("sha256:")
                    and str(event.get("data", {}).get("approval_signature", "")).startswith(
                        "base64:"
                    )
                ),
            )
            executed = await _wait_for_audit_event(
                client,
                event_type="ToolExecuted",
                session_id=sid,
                predicate=lambda event: (
                    str(event.get("data", {}).get("tool_name", "")) == "shell.exec"
                    and bool(event.get("data", {}).get("success")) is True
                    and str(event.get("data", {}).get("approval_level", ""))
                    == "signed_authorization"
                    and str(event.get("data", {}).get("approval_method", "")) == "kms"
                    and str(event.get("data", {}).get("approval_signer_key_id", ""))
                    == "kms:finance-primary"
                ),
            )
            assert approved["data"]["approval_review_surface"] == "provider_ui"
            assert approved["data"]["approval_binding_scope"] == "full_intent"
            assert approved["data"]["approval_third_party_verifiable"] is True
            assert executed["event_type"] == "ToolExecuted"
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
        if "TASK CLOSE-GATE SELF-CHECK" in user_content:
            return _complete_close_gate_result()
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
        'version: "1"\ndefault_require_confirmation: false\ndefault_capabilities:\n  - file.read\n'
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
        if "TASK CLOSE-GATE SELF-CHECK" in user_content:
            return _complete_close_gate_result()
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
        if "TASK CLOSE-GATE SELF-CHECK" in user_content:
            return _complete_close_gate_result()
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
        'version: "1"\ndefault_require_confirmation: false\ndefault_capabilities:\n  - file.read\n'
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
        if "TASK CLOSE-GATE SELF-CHECK" in user_content:
            return _complete_close_gate_result()
        return PlannerResult(
            output=PlannerOutput(assistant_response="Task stayed in task mode.", actions=[]),
            evaluated=[],
            attempts=1,
            provider_response=None,
            messages_sent=(),
        )

    monkeypatch.setattr(Planner, "propose", _task_admin_like_prompt_stays_task)
    policy_text = (
        'version: "1"\ndefault_require_confirmation: false\ndefault_capabilities:\n  - file.read\n'
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
        'version: "1"\ndefault_require_confirmation: false\ndefault_capabilities:\n  - file.read\n'
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


@pytest.mark.asyncio
async def test_behavioral_dev_loop_implement_review_remediate_close_smoke(
    tmp_path: Path,
) -> None:
    readme_before = Path("README.md").read_text(encoding="utf-8")
    implementation = tmp_path / "IMPLEMENTATION.md"
    implementation.write_text(
        """
## M4 — Minimal Dev Loop Orchestration

### M4 Punchlist
- [x] dev.implement works

### M4 Acceptance Criteria
- [x] Runtime wiring evidence recorded.
- [x] Validation evidence recorded.
- [x] Docs parity evidence recorded.
- [x] Review loop complete or deferrals explicitly recorded.

### M4 Review Findings Status (Round 1)
- [x] M4.R-open.1: closed.

### M4 Runtime Wiring Evidence
- Wired.

### M4 Validation Evidence
- `uv run pytest tests/behavioral/ -q` -> `ok`

## Worklog

- **2026-03-14**: **M4 implementation**
  - Summary: docs updated.
""".strip(),
        encoding="utf-8",
    )
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
                "claude": _fake_coding_agent_command("claude"),
            },
        },
    )
    try:
        implement = await client.call(
            "dev.implement",
            {
                "task": "Add a tiny implementation note to README.md.",
                "file_refs": ["README.md"],
                "agent": "codex",
            },
        )
        assert implement["success"] is True
        assert implement["proposal_ref"]
        assert "mode=build" in implement["summary"]

        review = await client.call(
            "dev.review",
            {
                "scope": "Review README.md for issues. OPPORTUNISTIC_EDIT if needed.",
                "file_refs": ["README.md"],
                "agent": "claude",
            },
        )
        assert review["success"] is True
        assert review["findings"]
        assert "mode=plan" in review["summary"]

        remediate = await client.call(
            "dev.remediate",
            {
                "findings": "Fix the README issue and keep the change proposal-first.",
                "file_refs": ["README.md"],
                "agent": "codex",
            },
        )
        assert remediate["success"] is True
        assert remediate["proposal_ref"]
        assert "mode=build" in remediate["summary"]

        close_result = await client.call(
            "dev.close",
            {"milestone": "M4", "implementation_path": str(implementation)},
        )
        assert close_result["ready"] is True
        assert close_result["missing_evidence"] == []
        assert Path("README.md").read_text(encoding="utf-8") == readme_before
    finally:
        await _shutdown_daemon(daemon_task, client)


@pytest.mark.asyncio
async def test_behavioral_dev_commands_are_admin_only_but_do_not_lockdown_untrusted_sessions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _planner_echo(
        self: Planner,
        *args: Any,
        **kwargs: Any,
    ) -> PlannerResult:
        _ = args, kwargs
        user_content = str(args[1]) if len(args) > 1 else ""
        if "TASK CLOSE-GATE SELF-CHECK" in user_content:
            return _complete_close_gate_result()
        return PlannerResult(
            output=PlannerOutput(
                assistant_response="Dev commands require the trusted admin CLI surface.",
                actions=[],
            ),
            evaluated=[],
            attempts=1,
            provider_response=None,
            messages_sent=(),
        )

    monkeypatch.setattr(Planner, "propose", _planner_echo)
    daemon_task, client, _config = await _start_daemon(tmp_path)
    try:
        created = await client.call(
            "session.create",
            {"channel": "matrix", "user_id": "alice", "workspace_id": "ops"},
        )
        sid = str(created["session_id"])
        result = await client.call(
            "session.message",
            {
                "session_id": sid,
                "channel": "matrix",
                "user_id": "alice",
                "workspace_id": "ops",
                "content": "dev implement a README.md change for me",
            },
        )

        assert result["response"] == "Dev commands require the trusted admin CLI surface."
        assert result["session_mode"] == "default"
        assert result["proposal_only"] is False
        assert not result.get("task_result")
        assert result["lockdown_level"] in {"off", "none", "", "normal"}

        audits = await client.call("audit.query", {"event_type": "TaskSessionStarted", "limit": 20})
        task_events = [
            event
            for event in audits.get("events", [])
            if str(event.get("data", {}).get("parent_session_id", "")) == sid
        ]
        assert task_events == []
    finally:
        await _shutdown_daemon(daemon_task, client)


@pytest.mark.asyncio
async def test_behavioral_dev_close_reports_not_ready_until_evidence_exists(
    tmp_path: Path,
) -> None:
    implementation = tmp_path / "IMPLEMENTATION.md"
    implementation.write_text(
        """
## M4 — Minimal Dev Loop Orchestration

### M4 Punchlist
- [ ] dev.implement works

### M4 Acceptance Criteria
- [ ] Runtime wiring evidence recorded.
- [ ] Validation evidence recorded.
- [ ] Docs parity evidence recorded.
- [ ] Review loop complete or deferrals explicitly recorded.

## Worklog
""".strip(),
        encoding="utf-8",
    )
    daemon_task, client, _config = await _start_daemon(tmp_path)
    try:
        result = await client.call(
            "dev.close",
            {"milestone": "M4", "implementation_path": str(implementation)},
        )

        assert result["ready"] is False
        assert "runtime_wiring_evidence_missing" in result["missing_evidence"]
        assert "validation_evidence_missing" in result["missing_evidence"]
        assert "docs_parity_evidence_missing" in result["missing_evidence"]
        assert "worklog_entry_missing" in result["missing_evidence"]
        assert "punchlist_incomplete" in result["missing_evidence"]
    finally:
        await _shutdown_daemon(daemon_task, client)
