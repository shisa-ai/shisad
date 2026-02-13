"""M3 process component extraction coverage."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from shisad.executors.connect_path import ConnectPathResult, NoopConnectPathProxy
from shisad.executors.sandbox import (
    DegradedModePolicy,
    ResourceLimits,
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


def test_m6_process_build_bwrap_command_mounts_paths_and_fallback_chdir(tmp_path: Path) -> None:
    read_dir = tmp_path / "read"
    read_dir.mkdir()
    write_parent = tmp_path / "write"
    write_parent.mkdir()
    script = tmp_path / "script.py"
    script.write_text("print('ok')", encoding="utf-8")

    runner = SandboxProcessRunner(
        connect_path_proxy=NoopConnectPathProxy(net_admin_available=False),
        bwrap_binary="/usr/bin/bwrap",
        nsjail_binary="/usr/sbin/nsjail",
    )
    config = SandboxConfig(
        tool_name="shell.exec",
        command=[sys.executable, str(script)],
        read_paths=[str(read_dir)],
        write_paths=[str(write_parent / "out.txt")],
        cwd=str(tmp_path / "missing-cwd"),
        degraded_mode=DegradedModePolicy.FAIL_OPEN,
        security_critical=False,
    )
    wrapped = runner.build_bwrap_command(config=config, command=[sys.executable, str(script)])
    assert wrapped[0] == "/usr/bin/bwrap"
    assert "--ro-bind" in wrapped
    assert str(read_dir) in wrapped
    assert "--bind" in wrapped
    assert str(write_parent) in wrapped
    chdir_index = wrapped.index("--chdir")
    assert wrapped[chdir_index + 1] == "/tmp"


def test_m6_process_build_bwrap_command_honors_existing_cwd(tmp_path: Path) -> None:
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    runner = SandboxProcessRunner(
        connect_path_proxy=NoopConnectPathProxy(net_admin_available=False),
        bwrap_binary="/usr/bin/bwrap",
        nsjail_binary="/usr/sbin/nsjail",
    )
    config = SandboxConfig(
        tool_name="shell.exec",
        command=[sys.executable, "-c", "print('ok')"],
        cwd=str(cwd),
        write_paths=[str(cwd)],
        degraded_mode=DegradedModePolicy.FAIL_OPEN,
        security_critical=False,
    )
    wrapped = runner.build_bwrap_command(config=config, command=config.command)
    chdir_index = wrapped.index("--chdir")
    assert wrapped[chdir_index + 1] == str(cwd)


def test_m6_process_build_nsjail_command_respects_mounts_and_network(tmp_path: Path) -> None:
    read_dir = tmp_path / "read"
    read_dir.mkdir()
    write_dir = tmp_path / "write"
    write_dir.mkdir()
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    runner = SandboxProcessRunner(
        connect_path_proxy=NoopConnectPathProxy(net_admin_available=False),
        bwrap_binary="/usr/bin/bwrap",
        nsjail_binary="/usr/sbin/nsjail",
    )
    config = SandboxConfig(
        tool_name="shell.exec",
        command=[sys.executable, "-c", "print('ok')"],
        read_paths=[str(read_dir)],
        write_paths=[str(write_dir)],
        cwd=str(cwd),
        degraded_mode=DegradedModePolicy.FAIL_OPEN,
        security_critical=False,
    )
    config.network.allow_network = True
    wrapped = runner.build_nsjail_command(config=config, command=config.command)
    assert wrapped[0] == "/usr/sbin/nsjail"
    assert "--disable_clone_newnet" in wrapped
    assert f"{read_dir}:{read_dir}" in wrapped
    assert f"{write_dir}:{write_dir}" in wrapped
    assert "--cwd" in wrapped
    assert str(cwd) in wrapped


def test_m6_process_preexec_limits_returns_none_without_resource(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_import = __import__

    def _fake_import(name: str, *args, **kwargs):  # type: ignore[no-untyped-def]
        if name == "resource":
            raise ImportError("no resource")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr("builtins.__import__", _fake_import)
    preexec = SandboxProcessRunner.preexec_limits(ResourceLimits(memory_mb=1, pids=1))
    assert preexec is None


def test_m6_process_preexec_limits_writes_degraded_warning(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[int, bytes]] = []

    def _setrlimit(_resource: int, _values: tuple[int, int]) -> None:
        raise OSError("unsupported")

    fake_resource = SimpleNamespace(
        RLIMIT_AS=1,
        RLIMIT_NPROC=2,
        setrlimit=_setrlimit,
    )
    monkeypatch.setitem(sys.modules, "resource", fake_resource)
    monkeypatch.setattr("os.write", lambda fd, data: calls.append((fd, data)))

    preexec = SandboxProcessRunner.preexec_limits(ResourceLimits(memory_mb=1, pids=1))
    assert preexec is not None
    preexec()
    assert calls
    assert b"resource limits degraded" in calls[0][1]


def test_m6_process_invoke_returns_blocked_reason_from_on_started(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _FakePopen:
        def __init__(self, *args, **kwargs):  # type: ignore[no-untyped-def]
            _ = args, kwargs
            self.pid = 321
            self.returncode = 143
            self.terminated = False

        def terminate(self) -> None:
            self.terminated = True

        def communicate(self, timeout: int | None = None) -> tuple[str, str]:
            _ = timeout
            return ("out", "err")

    monkeypatch.setattr(subprocess, "Popen", _FakePopen)
    stdout, stderr, exit_code, timed_out, blocked_reason = SandboxProcessRunner.invoke(
        ["echo", "ok"],
        env={},
        cwd=None,
        timeout_seconds=1,
        preexec=None,
        on_started=lambda _pid: "connect_path_unavailable",
    )
    assert stdout == "out"
    assert stderr == "err"
    assert exit_code == 143
    assert timed_out is False
    assert blocked_reason == "connect_path_unavailable"


def test_m6_process_invoke_timeout_sets_timed_out(monkeypatch: pytest.MonkeyPatch) -> None:
    class _FakePopen:
        def __init__(self, *args, **kwargs):  # type: ignore[no-untyped-def]
            _ = args, kwargs
            self.pid = 1
            self.returncode = 124
            self._first = True

        def kill(self) -> None:
            return

        def communicate(self, timeout: int | None = None) -> tuple[str, str]:
            if self._first:
                self._first = False
                raise subprocess.TimeoutExpired(cmd="x", timeout=timeout or 1)
            return ("timeout-out", "timeout-err")

    monkeypatch.setattr(subprocess, "Popen", _FakePopen)
    stdout, stderr, exit_code, timed_out, blocked_reason = SandboxProcessRunner.invoke(
        ["echo", "ok"],
        env={},
        cwd=None,
        timeout_seconds=1,
        preexec=None,
    )
    assert timed_out is True
    assert stdout == "timeout-out"
    assert stderr == "timeout-err"
    assert exit_code is None
    assert blocked_reason is None


def test_m6_process_invoke_handles_timeout_exception_from_popen(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _raise_timeout(*args, **kwargs):  # type: ignore[no-untyped-def]
        _ = args, kwargs
        raise subprocess.TimeoutExpired(cmd="x", timeout=1, output=b"o", stderr=b"e")

    monkeypatch.setattr(subprocess, "Popen", _raise_timeout)
    stdout, stderr, exit_code, timed_out, blocked_reason = SandboxProcessRunner.invoke(
        ["echo", "ok"],
        env={},
        cwd=None,
        timeout_seconds=1,
        preexec=None,
    )
    assert timed_out is True
    assert stdout == "o"
    assert stderr == "e"
    assert exit_code is None
    assert blocked_reason is None


def test_m6_process_run_process_blocks_when_connect_path_unavailable() -> None:
    class _DegradedConnectPathProxy:
        def enforce(self, *, allowed_ips: list[str], namespace_pid: int) -> ConnectPathResult:
            _ = allowed_ips, namespace_pid
            return ConnectPathResult(enforced=False, method="iptables", reason="not_enforced")

    runner = SandboxProcessRunner(
        connect_path_proxy=_DegradedConnectPathProxy(),  # type: ignore[arg-type]
        bwrap_binary="",
        nsjail_binary="",
    )
    backend = SandboxBackend(
        backend=SandboxType.CONTAINER,
        runtime="",
        enforcement=SandboxEnforcement(),
    )
    result = runner.run_process(
        SandboxConfig(
            tool_name="http_request",
            command=[sys.executable, "-c", "print('ok')"],
            degraded_mode=DegradedModePolicy.FAIL_CLOSED,
            security_critical=True,
        ),
        backend=backend,
        command=[sys.executable, "-c", "print('ok')"],
        env={},
        connect_path_allowed_ips=["93.184.216.34"],
        enforce_connect_path=True,
    )
    assert result.blocked_reason == "runtime_isolation_unavailable"


def test_m6_process_isolation_runtime_failed_and_to_text_helpers() -> None:
    assert (
        SandboxProcessRunner.isolation_runtime_failed(
            exit_code=1,
            stderr="Creating new namespace failed: Operation not permitted",
        )
        is True
    )
    assert (
        SandboxProcessRunner.isolation_runtime_failed(exit_code=0, stderr="permission denied")
        is False
    )
    assert SandboxProcessRunner.to_text(None) == ""
    assert SandboxProcessRunner.to_text(b"hello") == "hello"
    assert SandboxProcessRunner.to_text("world") == "world"


def test_m6_process_detect_usable_bwrap_handles_probe_outcomes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("shisad.executors.sandbox.process.shutil.which", lambda name: "")
    assert SandboxProcessRunner._detect_usable_bwrap() == ""

    monkeypatch.setattr(
        "shisad.executors.sandbox.process.shutil.which",
        lambda name: "/usr/bin/bwrap" if name == "bwrap" else "",
    )

    def _failed_probe(*args, **kwargs):  # type: ignore[no-untyped-def]
        _ = args, kwargs
        return SimpleNamespace(returncode=1)

    monkeypatch.setattr(subprocess, "run", _failed_probe)
    assert SandboxProcessRunner._detect_usable_bwrap() == ""

    def _raise_probe(*args, **kwargs):  # type: ignore[no-untyped-def]
        _ = args, kwargs
        raise OSError("probe failed")

    monkeypatch.setattr(subprocess, "run", _raise_probe)
    assert SandboxProcessRunner._detect_usable_bwrap() == ""

    def _ok_probe(*args, **kwargs):  # type: ignore[no-untyped-def]
        _ = args, kwargs
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(subprocess, "run", _ok_probe)
    assert SandboxProcessRunner._detect_usable_bwrap() == "/usr/bin/bwrap"
