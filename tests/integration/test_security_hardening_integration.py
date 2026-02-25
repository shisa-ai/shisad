"""M6 integration coverage for adversarial gating and leak-check flow."""

from __future__ import annotations

import asyncio
import json
import sys
from contextlib import suppress
from pathlib import Path

import pytest

from shisad.core.api.transport import ControlClient
from shisad.core.config import DaemonConfig
from shisad.daemon.runner import run_daemon
from shisad.security.adversarial import AdversarialMetrics, ci_gate
from shisad.security.firewall import ContentFirewall


@pytest.fixture
def model_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SHISAD_MODEL_BASE_URL", "https://api.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_PLANNER_BASE_URL", "https://planner.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_EMBEDDINGS_BASE_URL", "https://embed.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_MONITOR_BASE_URL", "https://monitor.example.com/v1")


async def _wait_for_socket(path: Path, timeout: float = 2.0) -> None:
    end = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < end:
        if path.exists():
            return
        await asyncio.sleep(0.01)
    raise TimeoutError(f"Timed out waiting for socket {path}")


async def _start_daemon(tmp_path: Path) -> tuple[asyncio.Task[None], ControlClient]:
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


def test_m6_t7_integration_adversarial_suite_all_pass() -> None:
    fixture_path = (
        Path(__file__).resolve().parents[1]
        / "adversarial"
        / "injection"
        / "direct_templates.json"
    )
    fixture = json.loads(
        fixture_path.read_text(encoding="utf-8")
    )
    templates = [str(item) for item in fixture["templates"]]
    targets = [str(item) for item in fixture["targets"]]
    tokens = [str(item) for item in fixture["tokens"]]
    firewall = ContentFirewall()
    active_templates = [
        template
        for template in templates
        if firewall.inspect(template.format(target=targets[0], token=tokens[0])).risk_score > 0.0
    ]
    variants = [
        template.format(target=target, token=token)
        for template in active_templates
        for target in targets
        for token in tokens
    ]
    assert len(variants) >= 50
    blocked = sum(1 for variant in variants if firewall.inspect(variant).risk_score > 0.0)
    asr = 1.0 - (blocked / float(len(variants)))
    metrics = AdversarialMetrics(
        attack_success_rate=asr,
        utility_retention=0.97,
        false_positive_rate=0.01,
        detection_latency_ms=35.0,
    )
    decision = ci_gate(metrics)
    assert decision.allowed is True


def test_m6_t8_integration_ci_gate_blocks_high_asr_pr() -> None:
    metrics = AdversarialMetrics(
        attack_success_rate=0.2,
        utility_retention=0.97,
        false_positive_rate=0.01,
        detection_latency_ms=20,
    )
    decision = ci_gate(metrics)
    assert decision.allowed is False
    assert "asr" in decision.reason


@pytest.mark.asyncio
async def test_m6_t12_cross_thread_high_overlap_requires_confirmation_and_audit_metadata(
    model_env: None,
    tmp_path: Path,
) -> None:
    # Restrict capabilities so http_request triggers stage2 → confirmation,
    # where the leak-check analysis can fire.
    (tmp_path / "policy.yaml").write_text(
        "version: \"1\"\ndefault_deny: false\n"
        "default_capabilities:\n"
        "  - file.read\n  - memory.read\n",
        encoding="utf-8",
    )
    daemon_task, client = await _start_daemon(tmp_path)
    try:
        created = await client.call("session.create", {"channel": "cli"})
        sid = created["session_id"]
        _ = await client.call(
            "session.message",
            {"session_id": sid, "content": "confidential ledger alpha bravo charlie delta report"},
        )
        result = await client.call(
            "tool.execute",
            {
                "session_id": sid,
                "tool_name": "http_request",
                "command": [sys.executable, "-c", "print('ok')"],
                "network_urls": ["https://api.good.example/upload"],
                "request_body": "alpha bravo charlie delta ledger report",
                "network": {
                    "allow_network": True,
                    "allowed_domains": ["api.good.example"],
                    "deny_private_ranges": True,
                    "deny_ip_literals": True,
                },
                "degraded_mode": "fail_open",
                "security_critical": False,
            },
        )
        assert result.get("confirmation_required") is True
        confirmation_id = str(result.get("confirmation_id", ""))
        pending = await client.call(
            "action.pending",
            {"session_id": sid, "status": "pending", "limit": 20},
        )
        row = next(
            item
            for item in pending["actions"]
            if item["confirmation_id"] == confirmation_id
        )
        leak_check = row.get("leak_check", {})
        assert leak_check.get("detected") is True
        assert leak_check.get("requires_confirmation") is True
        assert "Cross-thread overlap detected" in row.get("warnings", [])

        rejected = await client.call(
            "audit.query",
            {"event_type": "ToolRejected", "session_id": sid, "limit": 50},
        )
        assert any(
            "leakcheck:high_overlap_requires_confirmation"
            in str(event.get("data", {}).get("reason", ""))
            for event in rejected["events"]
        )
    finally:
        await _shutdown(daemon_task, client)


@pytest.mark.asyncio
async def test_m6_t13_explicit_forward_intent_allows_warning_trail(
    model_env: None,
    tmp_path: Path,
) -> None:
    # Restrict capabilities so http_request triggers stage2 → confirmation,
    # where the leak-check analysis can fire.
    (tmp_path / "policy.yaml").write_text(
        "version: \"1\"\ndefault_deny: false\n"
        "default_capabilities:\n"
        "  - file.read\n  - memory.read\n",
        encoding="utf-8",
    )
    daemon_task, client = await _start_daemon(tmp_path)
    try:
        created = await client.call("session.create", {"channel": "cli"})
        sid = created["session_id"]
        _ = await client.call(
            "session.message",
            {"session_id": sid, "content": "migration notes include alpha bravo charlie delta"},
        )
        result = await client.call(
            "tool.execute",
            {
                "session_id": sid,
                "tool_name": "http_request",
                "command": [sys.executable, "-c", "print('ok')"],
                "network_urls": ["https://api.good.example/upload"],
                "request_body": "alpha bravo charlie delta migration notes",
                "explicit_share_intent": True,
                "network": {
                    "allow_network": True,
                    "allowed_domains": ["api.good.example"],
                    "deny_private_ranges": True,
                    "deny_ip_literals": True,
                },
                "degraded_mode": "fail_open",
                "security_critical": False,
            },
        )
        assert result.get("confirmation_required") is True
        confirmation_id = str(result.get("confirmation_id", ""))
        pending = await client.call(
            "action.pending",
            {"session_id": sid, "status": "pending", "limit": 20},
        )
        row = next(
            item
            for item in pending["actions"]
            if item["confirmation_id"] == confirmation_id
        )
        leak_check = row.get("leak_check", {})
        assert leak_check.get("detected") is True
        assert leak_check.get("requires_confirmation") is False
        assert "Cross-thread overlap detected" in row.get("warnings", [])
    finally:
        await _shutdown(daemon_task, client)
