"""Integration coverage for daemon-backed signer registration and L3 approvals."""

from __future__ import annotations

import asyncio
import sys
from contextlib import suppress
from pathlib import Path
from typing import Any

import pytest

from shisad.core.api.transport import ControlClient
from shisad.core.config import DaemonConfig
from shisad.daemon.runner import run_daemon
from tests.helpers.signer import StubSignerService, generate_ed25519_private_key, public_key_pem


async def _wait_for_socket(path: Path, timeout: float = 5.0) -> None:
    end = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < end:
        if path.exists():
            return
        await asyncio.sleep(0.01)
    raise TimeoutError(f"Timed out waiting for socket {path}")


def _configure_model_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SHISAD_MODEL_BASE_URL", "https://api.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_PLANNER_BASE_URL", "https://planner.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_EMBEDDINGS_BASE_URL", "https://embed.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_MONITOR_BASE_URL", "https://monitor.example.com/v1")
    monkeypatch.setenv("SHISAD_MEMORY_MASTER_KEY", "integration-test-master-key")


async def _start_daemon(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    config_overrides: dict[str, Any] | None = None,
    policy_text: str | None = None,
) -> tuple[asyncio.Task[None], ControlClient]:
    _configure_model_env(monkeypatch)
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        policy_text or 'version: "1"\ndefault_require_confirmation: false\n',
        encoding="utf-8",
    )
    config_kwargs: dict[str, Any] = {
        "data_dir": tmp_path / "data",
        "socket_path": tmp_path / "control.sock",
        "policy_path": policy_path,
        "log_level": "INFO",
    }
    if config_overrides:
        config_kwargs.update(config_overrides)
    config = DaemonConfig(**config_kwargs)
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
async def test_signer_register_list_revoke_persists_across_restart(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_key = generate_ed25519_private_key()
    daemon_task, client = await _start_daemon(tmp_path, monkeypatch)
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
        assert registered["credential_id"] == "kms:finance-primary"

        listed = await client.call("signer.list", {"user_id": "alice"})
        assert listed["count"] == 1
        assert listed["entries"][0]["principal_id"] == "finance-owner"
        assert listed["entries"][0]["credential_id"] == "kms:finance-primary"
        assert listed["entries"][0]["algorithm"] == "ed25519"
        assert listed["entries"][0]["backend"] == "kms"
        assert listed["entries"][0]["revoked"] is False
    finally:
        await _shutdown_daemon(daemon_task, client)

    daemon_task, client = await _start_daemon(tmp_path, monkeypatch)
    try:
        listed = await client.call("signer.list", {"user_id": "alice"})
        assert listed["count"] == 1
        revoke = await client.call("signer.revoke", {"key_id": "kms:finance-primary"})
        assert revoke["revoked"] is True
        assert revoke["removed"] == 1
        listed_after = await client.call("signer.list", {"user_id": "alice"})
        assert listed_after["count"] == 0
    finally:
        await _shutdown_daemon(daemon_task, client)


@pytest.mark.asyncio
async def test_signer_confirmation_executes_and_records_l3_audit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
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
        daemon_task, client = await _start_daemon(
            tmp_path,
            monkeypatch,
            config_overrides={"signer_kms_url": signer_url},
            policy_text=policy_text,
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
                    "command": [sys.executable, "-c", "print('integration-l2')"],
                    "limits": {"timeout_seconds": 5, "output_bytes": 2048},
                    "degraded_mode": "fail_open",
                    "security_critical": False,
                },
            )
            assert proposed["allowed"] is False
            assert proposed["confirmation_required"] is True
            confirmation_id = str(proposed["confirmation_id"])

            pending = await client.call("action.pending", {"confirmation_id": confirmation_id})
            assert pending["count"] == 1
            action = pending["actions"][0]
            assert action["required_level"] == "signed_authorization"
            assert action["selected_backend_method"] == "kms"
            assert str(action["approval_envelope"]["intent_envelope_hash"]).startswith("sha256:")
            assert action["intent_envelope"]["schema_version"] == "shisad.intent.v1"

            confirmed = await client.call(
                "action.confirm",
                {
                    "confirmation_id": confirmation_id,
                    "decision_nonce": str(action["decision_nonce"]),
                    "reason": "integration_l2",
                },
            )
            assert confirmed["confirmed"] is True
            assert confirmed["status"] == "approved"
            assert confirmed["approval_level"] == "signed_authorization"
            assert confirmed["approval_method"] == "kms"

            events = await client.call(
                "audit.query",
                {"event_type": "ToolApproved", "session_id": sid, "limit": 20},
            )
            assert any(
                str(event.get("data", {}).get("approval_level", ""))
                == "signed_authorization"
                and str(event.get("data", {}).get("approval_method", "")) == "kms"
                and str(event.get("data", {}).get("approval_signer_key_id", ""))
                == "kms:finance-primary"
                and str(event.get("data", {}).get("approval_signature", "")).startswith("base64:")
                for event in events.get("events", [])
            )
        finally:
            await _shutdown_daemon(daemon_task, client)
