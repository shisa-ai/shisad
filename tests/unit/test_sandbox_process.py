"""M3 process component extraction coverage."""

from __future__ import annotations

import sys

from shisad.executors.connect_path import NoopConnectPathProxy
from shisad.executors.sandbox import (
    DegradedModePolicy,
    SandboxBackend,
    SandboxConfig,
    SandboxEnforcement,
    SandboxProcessRunner,
    SandboxType,
)


def test_m3_process_fail_closed_blocks_when_runtime_unavailable() -> None:
    runner = SandboxProcessRunner(connect_path_proxy=NoopConnectPathProxy())
    backend = SandboxBackend(
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
    result = runner.run_process(
        SandboxConfig(
            tool_name="shell.exec",
            command=[sys.executable, "-c", "print('ok')"],
            degraded_mode=DegradedModePolicy.FAIL_CLOSED,
            security_critical=True,
        ),
        backend=backend,
        command=[sys.executable, "-c", "print('ok')"],
        env={},
        connect_path_allowed_ips=[],
        enforce_connect_path=False,
    )
    assert result.blocked_reason == "runtime_isolation_unavailable"
    assert result.isolation_degraded is True


def test_m3_process_fail_open_executes_when_runtime_unavailable() -> None:
    runner = SandboxProcessRunner(connect_path_proxy=NoopConnectPathProxy())
    backend = SandboxBackend(
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
    result = runner.run_process(
        SandboxConfig(
            tool_name="shell.exec",
            command=[sys.executable, "-c", "print('ok')"],
            degraded_mode=DegradedModePolicy.FAIL_OPEN,
            security_critical=False,
        ),
        backend=backend,
        command=[sys.executable, "-c", "print('ok')"],
        env={},
        connect_path_allowed_ips=[],
        enforce_connect_path=False,
    )
    assert result.blocked_reason == ""
    assert result.exit_code == 0
    assert "ok" in result.stdout


def test_m3_process_default_backends_include_runtime_capabilities() -> None:
    runner = SandboxProcessRunner(connect_path_proxy=NoopConnectPathProxy())
    backends = runner.build_default_backends()
    assert set(backends.keys()) == {SandboxType.CONTAINER, SandboxType.NSJAIL, SandboxType.VM}


def test_m3_process_wrapper_passthrough_for_unknown_runtime() -> None:
    runner = SandboxProcessRunner(connect_path_proxy=NoopConnectPathProxy())
    backend = SandboxBackend(
        backend=SandboxType.NSJAIL,
        runtime="/tmp/not-supported-runtime",
        enforcement=SandboxEnforcement(),
    )
    command = [sys.executable, "-c", "print('ok')"]
    wrapped = runner.wrap_isolated_command(
        backend=backend,
        config=SandboxConfig(tool_name="shell.exec", command=command),
        command=command,
    )
    assert wrapped == command
