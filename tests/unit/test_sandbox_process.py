"""M3 process component extraction coverage."""

from __future__ import annotations

import os
import signal
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

import shisad.executors.sandbox.process as sandbox_process_module
from shisad.executors.connect_path import ConnectPathResult, NoopConnectPathProxy
from shisad.executors.sandbox import (
    DegradedModePolicy,
    ResourceLimits,
    SandboxBackend,
    SandboxConfig,
    SandboxEnforcement,
    SandboxPolicyEvaluator,
    SandboxProcessRunner,
    SandboxType,
)
from shisad.executors.sandbox.models import ContainmentProfile


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
            containment_profile=ContainmentProfile.EXPERT_HOST_FALLBACK,
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


def test_m3_process_kill_tree_falls_back_when_sigkill_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeProcess:
        pid = 12345

        def __init__(self) -> None:
            self.killed = False

        def kill(self) -> None:
            self.killed = True

    process = FakeProcess()
    signaled: list[tuple[object, signal.Signals]] = []

    monkeypatch.delattr(sandbox_process_module.signal, "SIGKILL", raising=False)
    monkeypatch.setattr(
        SandboxProcessRunner,
        "_signal_process_tree",
        lambda target, signum: signaled.append((target, signum)),
    )

    SandboxProcessRunner._kill_process_tree(process)

    assert signaled == []
    assert process.killed is True


def test_m3_process_default_backends_include_runtime_capabilities() -> None:
    runner = SandboxProcessRunner(connect_path_proxy=NoopConnectPathProxy())
    backends = runner.build_default_backends()
    assert set(backends.keys()) == {SandboxType.CONTAINER, SandboxType.NSJAIL, SandboxType.VM}


def test_u42r_network_enforcement_requires_bwrap_and_pasta() -> None:
    incomplete = SandboxProcessRunner(
        connect_path_proxy=NoopConnectPathProxy(net_admin_available=True),
        bwrap_binary="/usr/bin/bwrap",
        nsjail_binary="/usr/sbin/nsjail",
        pasta_binary="",
    ).build_default_backends()
    complete = SandboxProcessRunner(
        connect_path_proxy=NoopConnectPathProxy(net_admin_available=True),
        bwrap_binary="/usr/bin/bwrap",
        nsjail_binary="/usr/sbin/nsjail",
        pasta_binary="/usr/bin/pasta",
    ).build_default_backends()

    assert all(backend.enforcement.network for backend in incomplete.values())
    assert all(not backend.enforcement.dns_control for backend in incomplete.values())
    assert all(backend.enforcement.network for backend in complete.values())
    assert all(backend.enforcement.dns_control for backend in complete.values())
    local_config = SandboxConfig(
        tool_name="shell.exec",
        command=["echo", "ok"],
        containment_profile=ContainmentProfile.SUPPORTED,
    )
    assert (
        SandboxPolicyEvaluator().degraded_controls(
            local_config,
            incomplete[SandboxType.CONTAINER].enforcement,
        )
        == []
    )


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


def test_u42r_network_wrappers_keep_an_isolated_namespace() -> None:
    runner = SandboxProcessRunner(
        connect_path_proxy=NoopConnectPathProxy(net_admin_available=True),
        bwrap_binary="/usr/bin/bwrap",
        nsjail_binary="/usr/sbin/nsjail",
        pasta_binary="/usr/bin/pasta",
    )
    config = SandboxConfig(
        tool_name="http.request",
        command=["curl", "https://api.good.example/data"],
    )
    config.network.allow_network = True

    bwrap = runner.build_bwrap_command(
        config=config,
        command=config.command,
        network_block_fd=19,
    )
    nsjail = runner.build_nsjail_command(config=config, command=config.command)

    assert "--unshare-net" in bwrap
    assert bwrap[bwrap.index("--cap-drop") + 1] == "ALL"
    assert bwrap[bwrap.index("--block-fd") + 1] == "19"
    assert "--disable_clone_newnet" not in nsjail


def test_u42r_network_command_is_released_only_after_connect_path_enforcement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []

    class _EnforcedConnectPathProxy:
        net_admin_available = True

        def enforce(self, *, allowed_ips: list[str], namespace_pid: int) -> ConnectPathResult:
            assert allowed_ips == ["93.184.216.34"]
            assert namespace_pid == 321
            events.append("connect-path")
            return ConnectPathResult(enforced=True, method="iptables", reason="enforced")

    runner = SandboxProcessRunner(
        connect_path_proxy=_EnforcedConnectPathProxy(),  # type: ignore[arg-type]
        bwrap_binary="/usr/bin/bwrap",
        nsjail_binary="/usr/sbin/nsjail",
        pasta_binary="/usr/bin/pasta",
    )
    backend = runner.build_default_backends()[SandboxType.CONTAINER]
    monkeypatch.setattr(
        runner,
        "_attach_pasta_network",
        lambda namespace_pid, **_kwargs: events.append(f"pasta:{namespace_pid}") or "",
    )
    monkeypatch.setattr(sandbox_process_module.secrets, "token_hex", lambda _size: "marker")

    def _invoke(
        command: list[str],
        **kwargs: object,
    ) -> tuple[str, str, int | None, bool, str | None]:
        assert command[0] == "/usr/bin/bwrap"
        assert "--unshare-net" in command
        assert "--block-fd" in command
        assert "--info-fd" in command
        assert command.count("--ro-bind-data") == 2
        assert "/etc/resolv.conf" in command
        assert "/etc/hosts" in command
        inherited_fds = tuple(kwargs.get("pass_fds", ()))
        assert len(inherited_fds) == 4
        info_write_fd = int(command[command.index("--info-fd") + 1])
        assert info_write_fd in inherited_fds
        assert kwargs.get("namespace_pid_fd") not in inherited_fds
        assert kwargs.get("close_after_spawn_fds") == (info_write_fd,)
        assert os.pread(inherited_fds[1], 4096, 0) == (
            b"nameserver 127.0.0.1\noptions timeout:1 attempts:1\n"
        )
        assert os.pread(inherited_fds[2], 4096, 0) == (
            b"127.0.0.1 localhost\n93.184.216.34 api.good.example\n"
        )
        SandboxProcessRunner._close_fd(info_write_fd)
        on_started = kwargs.get("on_started")
        assert callable(on_started)
        assert on_started(321) is None
        assert os.read(inherited_fds[0], 1) == b"1"
        events.append("command")
        return "ok\n", "shisad-exec-marker:marker\n", 0, False, None

    monkeypatch.setattr(runner, "invoke", _invoke)
    config = SandboxConfig(
        tool_name="http.request",
        command=["curl", "https://api.good.example/data"],
        containment_profile=ContainmentProfile.SUPPORTED,
    )
    config.network.allow_network = True
    config.network.allowed_domains = ["api.good.example"]

    result = runner.run_process(
        config,
        backend=backend,
        command=config.command,
        env={},
        connect_path_allowed_ips=["93.184.216.34"],
        enforce_connect_path=True,
    )

    assert events == ["pasta:321", "connect-path", "command"]
    assert result.blocked_reason == ""
    assert result.isolation_degraded is False
    assert result.actual_runtime == "bwrap+pasta"
    assert result.host_fallback_used is False
    assert result.connect_path_result is not None
    assert result.connect_path_result.enforced is True


def test_u42r_pasta_transport_disables_dns_and_port_forwarding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = SandboxProcessRunner(
        connect_path_proxy=NoopConnectPathProxy(net_admin_available=True),
        bwrap_binary="/usr/bin/bwrap",
        nsjail_binary="",
        pasta_binary="/usr/bin/pasta",
    )
    captured: list[list[str]] = []
    monkeypatch.setattr(runner, "_wait_for_isolated_network_namespace", lambda _pid: "")

    def _run(command: list[str], **_kwargs: object) -> SimpleNamespace:
        captured.append(list(command))
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(subprocess, "run", _run)

    assert runner._attach_pasta_network(321) == ""
    assert len(captured) == 1
    command = captured[0]
    assert "--dns-forward" not in command
    assert command[command.index("-D") + 1] == "none"
    assert "--no-splice" in command
    for option in ("-t", "-u", "-T", "-U"):
        assert command[command.index(option) + 1] == "none"


def test_u42r_network_hosts_file_rejects_wildcards_literals_and_injection() -> None:
    config = SandboxConfig(
        tool_name="http.request",
        command=["curl", "--url=https://Command.Example/path"],
        network_urls=["https://API.Good.Example/data", "https://127.0.0.1/"],
    )
    config.network.allowed_domains = [
        "literal.example",
        "*.wildcard.example",
        "bad host.example",
    ]

    hosts_file = SandboxProcessRunner._network_hosts_file(
        config,
        config.command,
        ["93.184.216.34"],
    )

    assert hosts_file == (
        b"127.0.0.1 localhost\n"
        b"93.184.216.34 api.good.example\n"
        b"93.184.216.34 command.example\n"
        b"93.184.216.34 literal.example\n"
    )


@pytest.mark.parametrize(
    ("payload", "expected_pid"),
    [
        (b'{\n "child-pid": 321,\n "net-namespace": 99\n}\n', 321),
        (b'{"child-pid": 0}\n', 0),
        (b'{"child-pid": true}\n', 0),
        (b"not-json\n", 0),
    ],
)
def test_u42r_bwrap_status_uses_structural_sandbox_child_pid(
    payload: bytes,
    expected_pid: int,
) -> None:
    read_fd, write_fd = os.pipe()
    try:
        os.write(write_fd, payload)
        os.close(write_fd)
        write_fd = -1
        assert SandboxProcessRunner._read_bwrap_child_pid(read_fd) == expected_pid
    finally:
        if write_fd >= 0:
            os.close(write_fd)
        os.close(read_fd)


def test_u42r_invoke_delivers_bwrap_child_pid_to_boundary_callback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    read_fd, write_fd = os.pipe()
    observed: list[int] = []

    class _Process:
        pid = 111
        returncode = 0

        @staticmethod
        def communicate(*, timeout: float | None = None) -> tuple[str, str]:
            _ = timeout
            return "", ""

    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: _Process())
    try:
        os.write(write_fd, b'{"child-pid": 321, "net-namespace": 99}\n')
        result = SandboxProcessRunner.invoke(
            ["/usr/bin/bwrap"],
            env={},
            cwd=None,
            timeout_seconds=1,
            preexec=None,
            on_started=lambda pid: observed.append(pid) or None,
            pass_fds=(write_fd,),
            namespace_pid_fd=read_fd,
            close_after_spawn_fds=(write_fd,),
        )
        write_fd = -1
    finally:
        if write_fd >= 0:
            os.close(write_fd)
        os.close(read_fd)

    assert result == ("", "", 0, False, None)
    assert observed == [321]


def test_u42r_network_info_fd_cleanup_does_not_close_reused_descriptor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = SandboxProcessRunner(
        connect_path_proxy=NoopConnectPathProxy(net_admin_available=True),
        bwrap_binary="/usr/bin/bwrap",
        nsjail_binary="",
        pasta_binary="/usr/bin/pasta",
    )
    backend = runner.build_default_backends()[SandboxType.CONTAINER]
    reused_fd = -1
    monkeypatch.setattr(sandbox_process_module.secrets, "token_hex", lambda _size: "marker")

    def _invoke(command: list[str], **kwargs: object):  # type: ignore[no-untyped-def]
        nonlocal reused_fd
        _ = command
        close_after_spawn_fds = tuple(kwargs.get("close_after_spawn_fds", ()))
        assert len(close_after_spawn_fds) == 1
        os.close(close_after_spawn_fds[0])
        reused_fd = os.open("/dev/null", os.O_RDONLY)
        assert reused_fd == close_after_spawn_fds[0]
        return "", "shisad-exec-marker:marker\n", 0, False, None

    monkeypatch.setattr(runner, "invoke", _invoke)
    config = SandboxConfig(
        tool_name="http.request",
        command=["curl", "https://api.good.example/data"],
        containment_profile=ContainmentProfile.SUPPORTED,
    )
    config.network.allow_network = True

    try:
        runner.run_process(
            config,
            backend=backend,
            command=config.command,
            env={},
            connect_path_allowed_ips=["93.184.216.34"],
            enforce_connect_path=True,
        )
        os.fstat(reused_fd)
    finally:
        if reused_fd >= 0:
            SandboxProcessRunner._close_fd(reused_fd)


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


def test_u42r_filesystem_targets_match_implicit_bwrap_mount_surface(tmp_path: Path) -> None:
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    executable = tmp_path / "tools" / "runner"
    executable.parent.mkdir()
    executable.write_text("#!/bin/sh\n", encoding="utf-8")
    absolute_argument = tmp_path / "secret.txt"
    absolute_argument.write_text("secret", encoding="utf-8")
    relative_argument = Path("relative.txt")

    targets = SandboxProcessRunner.filesystem_targets_for_command(
        [str(executable), str(absolute_argument), str(relative_argument)],
        cwd=str(cwd),
    )

    assert targets == [str(cwd.resolve()), str(tmp_path.resolve())]


def test_u42r_runtime_mounts_only_preinjection_authorized_command_atoms(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = tmp_path / "secret" / "value"
    secret.parent.mkdir()
    secret.write_text("sensitive", encoding="utf-8")
    runner = SandboxProcessRunner(
        connect_path_proxy=NoopConnectPathProxy(),
        bwrap_binary="/usr/bin/bwrap",
        nsjail_binary="",
        pasta_binary="",
    )
    backend = runner.build_default_backends()[SandboxType.CONTAINER]
    monkeypatch.setattr(sandbox_process_module.secrets, "token_hex", lambda _size: "marker")
    wrapped_commands: list[list[str]] = []

    def _invoke(command: list[str], **_kwargs: object):  # type: ignore[no-untyped-def]
        wrapped_commands.append(list(command))
        return "ok\n", "shisad-exec-marker:marker\n", 0, False, None

    monkeypatch.setattr(runner, "invoke", _invoke)
    config = SandboxConfig(
        tool_name="shell.exec",
        command=["echo", "SHISAD_SECRET_PLACEHOLDER_00000000000000000000000000000000"],
        containment_profile=ContainmentProfile.SUPPORTED,
    )

    result = runner.run_process(
        config,
        backend=backend,
        command=["echo", str(secret)],
        env={},
        connect_path_allowed_ips=[],
        enforce_connect_path=False,
    )

    assert result.blocked_reason == ""
    assert len(wrapped_commands) == 1
    assert str(secret.parent) not in wrapped_commands[0]


def test_u42r_postauthorization_executable_rewrite_fails_before_invoke(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = SandboxProcessRunner(
        connect_path_proxy=NoopConnectPathProxy(),
        bwrap_binary="/usr/bin/bwrap",
        nsjail_binary="",
        pasta_binary="",
    )
    backend = runner.build_default_backends()[SandboxType.CONTAINER]
    monkeypatch.setattr(
        runner,
        "invoke",
        lambda *args, **kwargs: pytest.fail("rewritten executable must not be invoked"),
    )
    config = SandboxConfig(
        tool_name="skill.credential-tool.run",
        command=["SHISAD_SECRET_PLACEHOLDER_00000000000000000000000000000000"],
        containment_profile=ContainmentProfile.SUPPORTED,
    )

    result = runner.run_process(
        config,
        backend=backend,
        command=["/tmp/injected-executable"],
        env={},
        connect_path_allowed_ips=[],
        enforce_connect_path=False,
    )

    assert result.blocked_reason == "executable_changed_after_authorization"
    assert result.host_fallback_used is False


def test_u42r_network_setup_error_fails_closed_before_invoke(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = SandboxProcessRunner(
        connect_path_proxy=NoopConnectPathProxy(net_admin_available=True),
        bwrap_binary="/usr/bin/bwrap",
        nsjail_binary="",
        pasta_binary="/usr/bin/pasta",
    )
    backend = runner.build_default_backends()[SandboxType.CONTAINER]
    monkeypatch.setattr(os, "pipe", lambda: (_ for _ in ()).throw(OSError("fd limit")))
    monkeypatch.setattr(
        runner,
        "invoke",
        lambda *args, **kwargs: pytest.fail("command must not be invoked"),
    )
    config = SandboxConfig(
        tool_name="http.request",
        command=["curl", "https://api.good.example/data"],
        containment_profile=ContainmentProfile.SUPPORTED,
    )
    config.network.allow_network = True

    result = runner.run_process(
        config,
        backend=backend,
        command=config.command,
        env={},
        connect_path_allowed_ips=["93.184.216.34"],
        enforce_connect_path=True,
    )

    assert result.blocked_reason == "runtime_isolation_unavailable"
    assert result.isolation_degraded is True
    assert result.connect_path_degraded is True


def test_u42r_connect_path_exception_fails_closed_before_command_release(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _BrokenConnectPathProxy:
        def enforce(self, *, allowed_ips: list[str], namespace_pid: int) -> ConnectPathResult:
            _ = allowed_ips, namespace_pid
            raise RuntimeError("iptables helper failed")

    runner = SandboxProcessRunner(
        connect_path_proxy=_BrokenConnectPathProxy(),  # type: ignore[arg-type]
        bwrap_binary="/usr/bin/bwrap",
        nsjail_binary="",
        pasta_binary="/usr/bin/pasta",
    )
    backend = runner.build_default_backends()[SandboxType.CONTAINER]
    monkeypatch.setattr(runner, "_attach_pasta_network", lambda _pid: "")

    def _invoke(command: list[str], **kwargs: object):  # type: ignore[no-untyped-def]
        _ = command
        for fd in tuple(kwargs.get("close_after_spawn_fds", ())):
            SandboxProcessRunner._close_fd(int(fd))
        on_started = kwargs.get("on_started")
        assert callable(on_started)
        reason = on_started(321)
        return "", "", 137, False, reason

    monkeypatch.setattr(runner, "invoke", _invoke)
    config = SandboxConfig(
        tool_name="http.request",
        command=["curl", "https://api.good.example/data"],
        containment_profile=ContainmentProfile.SUPPORTED,
    )
    config.network.allow_network = True

    result = runner.run_process(
        config,
        backend=backend,
        command=config.command,
        env={},
        connect_path_allowed_ips=["93.184.216.34"],
        enforce_connect_path=True,
    )

    assert result.blocked_reason == "connect_path_unavailable"
    assert result.connect_path_degraded is True
    assert result.connect_path_result is not None
    assert result.connect_path_result.reason == "connect_path_failed:RuntimeError"


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
    assert "--disable_clone_newnet" not in wrapped
    assert f"{read_dir}:{read_dir}" in wrapped
    assert f"{write_dir}:{write_dir}" in wrapped
    assert "--cwd" in wrapped
    assert str(cwd) in wrapped


def test_m6_process_build_nsjail_command_omits_disabled_address_limit() -> None:
    runner = SandboxProcessRunner(
        connect_path_proxy=NoopConnectPathProxy(net_admin_available=False),
        bwrap_binary="/usr/bin/bwrap",
        nsjail_binary="/usr/sbin/nsjail",
    )
    config = SandboxConfig(
        tool_name="browser.navigate",
        command=[sys.executable, "-c", "print('ok')"],
        limits=ResourceLimits(memory_mb=2048, address_space_mb=0),
        degraded_mode=DegradedModePolicy.FAIL_OPEN,
        security_critical=False,
    )

    wrapped = runner.build_nsjail_command(config=config, command=config.command)

    assert "--rlimit_as" not in wrapped


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


def test_m6_process_preexec_limits_skips_zero_limits(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[int, tuple[int, int]]] = []

    fake_resource = SimpleNamespace(
        RLIMIT_AS=1,
        RLIMIT_NPROC=2,
        setrlimit=lambda resource_id, values: calls.append((resource_id, values)),
    )
    monkeypatch.setitem(sys.modules, "resource", fake_resource)

    preexec = SandboxProcessRunner.preexec_limits(
        ResourceLimits(memory_mb=2048, address_space_mb=0, pids=0)
    )
    assert preexec is not None
    preexec()

    assert calls == []


def test_m6_process_invoke_blocks_when_memory_monitor_limit_exceeded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _FakePopen:
        def __init__(self, *args, **kwargs):  # type: ignore[no-untyped-def]
            _ = args, kwargs
            self.pid = 321
            self.returncode = None
            self.killed = False

        def kill(self) -> None:
            self.killed = True
            self.returncode = -9

        def communicate(self, timeout: int | None = None) -> tuple[str, str]:
            _ = timeout
            if not self.killed:
                raise subprocess.TimeoutExpired(cmd="x", timeout=1)
            return ("out", "err")

    monkeypatch.setattr(subprocess, "Popen", _FakePopen)
    monkeypatch.setattr(SandboxProcessRunner, "_process_tree_rss_bytes", lambda _pid: 2_000_000)
    monkeypatch.setattr(
        SandboxProcessRunner,
        "_kill_process_tree",
        lambda process: process.kill(),
    )

    stdout, stderr, exit_code, timed_out, blocked_reason = SandboxProcessRunner.invoke(
        ["echo", "ok"],
        env={},
        cwd=None,
        timeout_seconds=1,
        preexec=None,
        memory_mb=1,
    )

    assert timed_out is False
    assert stdout == "out"
    assert "resource limit exceeded: memory_mb=1" in stderr
    assert exit_code is None
    assert blocked_reason == "resource_limit_exceeded"


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


def test_u42r_invoke_terminates_blocked_process_when_boundary_callback_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _FakePopen:
        def __init__(self, *args, **kwargs):  # type: ignore[no-untyped-def]
            _ = args, kwargs
            self.pid = 321
            self.returncode = 137
            self.killed = False

        def kill(self) -> None:
            self.killed = True

        def communicate(self, timeout: int | None = None) -> tuple[str, str]:
            _ = timeout
            assert self.killed is True
            return ("", "")

    process: _FakePopen | None = None

    def _popen(*args, **kwargs):  # type: ignore[no-untyped-def]
        nonlocal process
        process = _FakePopen(*args, **kwargs)
        return process

    def _broken_boundary(_pid: int) -> str | None:
        raise RuntimeError("boundary setup failed")

    monkeypatch.setattr(subprocess, "Popen", _popen)
    stdout, stderr, exit_code, timed_out, blocked_reason = SandboxProcessRunner.invoke(
        ["echo", "ok"],
        env={},
        cwd=None,
        timeout_seconds=1,
        preexec=None,
        on_started=_broken_boundary,
    )

    assert process is not None
    assert process.killed is True
    assert stdout == ""
    assert stderr == "process start callback failed: RuntimeError"
    assert exit_code == 137
    assert timed_out is False
    assert blocked_reason == "process_start_callback_failed:RuntimeError"


def test_m6_process_invoke_timeout_sets_timed_out(monkeypatch: pytest.MonkeyPatch) -> None:
    class _FakePopen:
        def __init__(self, *args, **kwargs):  # type: ignore[no-untyped-def]
            _ = args, kwargs
            self.pid = 321
            self.returncode = 124
            self.killed = False

        def kill(self) -> None:
            self.killed = True

        def communicate(self, timeout: int | None = None) -> tuple[str, str]:
            if not self.killed:
                raise subprocess.TimeoutExpired(cmd="x", timeout=timeout or 1)
            return ("timeout-out", "timeout-err")

    monkeypatch.setattr(subprocess, "Popen", _FakePopen)
    monkeypatch.setattr(
        SandboxProcessRunner,
        "_kill_process_tree",
        lambda process: process.kill(),
    )
    stdout, stderr, exit_code, timed_out, blocked_reason = SandboxProcessRunner.invoke(
        ["echo", "ok"],
        env={},
        cwd=None,
        timeout_seconds=0,
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


def test_u42r_process_invoke_returns_structured_launch_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _missing_runtime(*args, **kwargs):  # type: ignore[no-untyped-def]
        _ = args, kwargs
        raise FileNotFoundError("runtime disappeared")

    monkeypatch.setattr(subprocess, "Popen", _missing_runtime)
    read_fd, write_fd = os.pipe()
    try:
        stdout, stderr, exit_code, timed_out, blocked_reason = SandboxProcessRunner.invoke(
            ["/missing/bwrap", "--", "echo", "ok"],
            env={},
            cwd=None,
            timeout_seconds=1,
            preexec=None,
            pass_fds=(write_fd,),
            close_after_spawn_fds=(write_fd,),
        )
        with pytest.raises(OSError):
            os.fstat(write_fd)
    finally:
        SandboxProcessRunner._close_fd(read_fd)
        SandboxProcessRunner._close_fd(write_fd)

    assert stdout == ""
    assert stderr == "process launch failed: FileNotFoundError"
    assert exit_code is None
    assert timed_out is False
    assert blocked_reason == "process_launch_failed:FileNotFoundError"


def test_u42r_process_invoke_kills_spawned_process_on_collection_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _FakePopen:
        def __init__(self, *args, **kwargs):  # type: ignore[no-untyped-def]
            _ = args, kwargs
            self.pid = 321
            self.returncode = None
            self.killed = False
            self.waited = False

        def communicate(self, timeout: float | None = None) -> tuple[str, str]:
            _ = timeout
            raise ValueError("decode failed")

        def kill(self) -> None:
            self.killed = True
            self.returncode = 137

        def wait(self, timeout: float | None = None) -> int:
            _ = timeout
            assert self.killed is True
            self.waited = True
            return 137

    process: _FakePopen | None = None

    def _popen(*args, **kwargs):  # type: ignore[no-untyped-def]
        nonlocal process
        process = _FakePopen(*args, **kwargs)
        return process

    monkeypatch.setattr(subprocess, "Popen", _popen)

    stdout, stderr, exit_code, timed_out, blocked_reason = SandboxProcessRunner.invoke(
        ["echo", "ok"],
        env={},
        cwd=None,
        timeout_seconds=1,
        preexec=None,
    )

    assert process is not None
    assert process.killed is True
    assert process.waited is True
    assert stdout == ""
    assert stderr == "process collection failed: ValueError"
    assert exit_code is None
    assert timed_out is False
    assert blocked_reason == "process_collection_failed:ValueError"


def test_u42r3_expert_post_spawn_collection_failure_never_replays_on_host(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = SandboxProcessRunner(
        connect_path_proxy=NoopConnectPathProxy(),
        bwrap_binary="/usr/bin/bwrap",
        nsjail_binary="",
        pasta_binary="",
    )
    backend = runner.build_default_backends()[SandboxType.CONTAINER]
    launched: list[list[str]] = []
    processes: list[object] = []
    monkeypatch.setattr(sandbox_process_module.secrets, "token_hex", lambda _size: "marker")

    class _Process:
        pid = 321

        def __init__(self) -> None:
            self.returncode: int | None = None
            self.killed = False

        def communicate(self, timeout: float | None = None) -> tuple[str, str]:
            _ = timeout
            raise ValueError("decode failed after child effect")

        def kill(self) -> None:
            self.killed = True
            self.returncode = 137

        def wait(self, timeout: float | None = None) -> int:
            _ = timeout
            assert self.killed is True
            return 137

    def _popen(command: list[str], **_kwargs: object) -> _Process:
        launched.append(list(command))
        process = _Process()
        processes.append(process)
        return process

    monkeypatch.setattr(subprocess, "Popen", _popen)
    config = SandboxConfig(
        tool_name="shell.exec",
        command=["effectful-command"],
        containment_profile=ContainmentProfile.EXPERT_HOST_FALLBACK,
        degraded_mode=DegradedModePolicy.FAIL_OPEN,
        security_critical=False,
    )

    result = runner.run_process(
        config,
        backend=backend,
        command=config.command,
        env={},
        connect_path_allowed_ips=[],
        enforce_connect_path=False,
    )

    assert len(launched) == 1
    assert len(processes) == 1
    assert result.blocked_reason == "process_collection_failed:ValueError"
    assert result.host_fallback_used is False
    assert result.actual_runtime == "bwrap"
    assert result.isolation_degraded is True


def test_u42r3_expert_pre_spawn_launch_failure_still_falls_back_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = SandboxProcessRunner(
        connect_path_proxy=NoopConnectPathProxy(),
        bwrap_binary="/usr/bin/bwrap",
        nsjail_binary="",
        pasta_binary="",
    )
    backend = runner.build_default_backends()[SandboxType.CONTAINER]
    calls: list[list[str]] = []
    monkeypatch.setattr(sandbox_process_module.secrets, "token_hex", lambda _size: "marker")

    def _invoke(command: list[str], **_kwargs: object):  # type: ignore[no-untyped-def]
        calls.append(list(command))
        if len(calls) == 1:
            return (
                "",
                "process launch failed: FileNotFoundError",
                None,
                False,
                "process_launch_failed:FileNotFoundError",
            )
        return "host-ok\n", "", 0, False, None

    monkeypatch.setattr(runner, "invoke", _invoke)
    config = SandboxConfig(
        tool_name="shell.exec",
        command=["working-command"],
        containment_profile=ContainmentProfile.EXPERT_HOST_FALLBACK,
        degraded_mode=DegradedModePolicy.FAIL_OPEN,
        security_critical=False,
    )

    result = runner.run_process(
        config,
        backend=backend,
        command=config.command,
        env={},
        connect_path_allowed_ips=[],
        enforce_connect_path=False,
    )

    assert len(calls) == 2
    assert result.stdout == "host-ok\n"
    assert result.blocked_reason == ""
    assert result.host_fallback_used is True
    assert result.actual_runtime == "host"


def test_u42r_process_invoke_preserves_invalid_utf8_as_replacement_text() -> None:
    stdout, stderr, exit_code, timed_out, blocked_reason = SandboxProcessRunner.invoke(
        [sys.executable, "-c", "import os; os.write(2, b'\\xff'); print('ok')"],
        env={},
        cwd=None,
        timeout_seconds=2,
        preexec=None,
    )

    assert stdout == "ok\n"
    assert stderr == "�"
    assert exit_code == 0
    assert timed_out is False
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


def test_u42r_child_stderr_cannot_trigger_expert_host_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = SandboxProcessRunner(
        connect_path_proxy=NoopConnectPathProxy(),
        bwrap_binary="/usr/bin/bwrap",
        nsjail_binary="",
        pasta_binary="",
    )
    backend = runner.build_default_backends()[SandboxType.CONTAINER]
    calls: list[list[str]] = []
    monkeypatch.setattr(sandbox_process_module.secrets, "token_hex", lambda _size: "marker")

    def _invoke(command: list[str], **_kwargs: object):  # type: ignore[no-untyped-def]
        calls.append(list(command))
        return (
            "",
            "shisad-exec-marker:marker\napplication: permission denied in namespace\n",
            1,
            False,
            None,
        )

    monkeypatch.setattr(runner, "invoke", _invoke)
    config = SandboxConfig(
        tool_name="shell.exec",
        command=["failing-command"],
        containment_profile=ContainmentProfile.EXPERT_HOST_FALLBACK,
        degraded_mode=DegradedModePolicy.FAIL_OPEN,
        security_critical=False,
    )

    result = runner.run_process(
        config,
        backend=backend,
        command=config.command,
        env={},
        connect_path_allowed_ips=[],
        enforce_connect_path=False,
    )

    assert len(calls) == 1
    assert result.exit_code == 1
    assert result.isolation_degraded is False
    assert result.host_fallback_used is False
    assert result.actual_runtime == "bwrap"
    assert "shisad-exec-marker" not in result.stderr
    assert "permission denied in namespace" in result.stderr


def test_u42r_failed_execution_marker_write_cannot_reach_original_command(
    tmp_path: Path,
) -> None:
    side_effect = tmp_path / "must-not-exist"
    instrumented = SandboxProcessRunner._instrument_command(
        [sys.executable, "-c", f"from pathlib import Path; Path({str(side_effect)!r}).touch()"],
        "shisad-exec-marker:test",
    )

    completed = subprocess.run(
        ["/bin/sh", "-c", 'exec 2>&-; exec "$@"', "outer", *instrumented],
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode != 0
    assert not side_effect.exists()


def test_u42r_expert_network_boundary_failure_falls_back_once_with_truthful_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = SandboxProcessRunner(
        connect_path_proxy=NoopConnectPathProxy(net_admin_available=True),
        bwrap_binary="/usr/bin/bwrap",
        nsjail_binary="",
        pasta_binary="/usr/bin/pasta",
    )
    backend = runner.build_default_backends()[SandboxType.CONTAINER]
    calls: list[list[str]] = []
    monkeypatch.setattr(runner, "_attach_pasta_network", lambda *args, **kwargs: "failed")

    def _invoke(command: list[str], **kwargs: object):  # type: ignore[no-untyped-def]
        calls.append(list(command))
        for fd in tuple(kwargs.get("close_after_spawn_fds", ())):
            SandboxProcessRunner._close_fd(int(fd))
        on_started = kwargs.get("on_started")
        if callable(on_started):
            assert on_started(321) == "connect_path_unavailable"
            return "", "", 143, False, "connect_path_unavailable"
        return "host-ok\n", "", 0, False, None

    monkeypatch.setattr(runner, "invoke", _invoke)
    config = SandboxConfig(
        tool_name="http.request",
        command=["curl", "https://api.good.example/data"],
        containment_profile=ContainmentProfile.EXPERT_HOST_FALLBACK,
        degraded_mode=DegradedModePolicy.FAIL_OPEN,
        security_critical=False,
    )
    config.network.allow_network = True

    result = runner.run_process(
        config,
        backend=backend,
        command=config.command,
        env={},
        connect_path_allowed_ips=["93.184.216.34"],
        enforce_connect_path=True,
    )

    assert len(calls) == 2
    assert result.stdout == "host-ok\n"
    assert result.host_fallback_used is True
    assert result.actual_runtime == "host"
    assert result.connect_path_degraded is True
    assert result.connect_path_result is not None
    assert result.connect_path_result.enforced is False
    assert result.connect_path_result.reason == "expert_host_fallback"


def test_u42r_supported_wrapper_launch_failure_returns_actionable_block(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = SandboxProcessRunner(
        connect_path_proxy=NoopConnectPathProxy(),
        bwrap_binary="/usr/bin/bwrap",
        nsjail_binary="",
        pasta_binary="",
    )
    backend = runner.build_default_backends()[SandboxType.CONTAINER]
    monkeypatch.setattr(
        runner,
        "invoke",
        lambda *args, **kwargs: (
            "",
            "process launch failed: FileNotFoundError",
            None,
            False,
            "process_launch_failed:FileNotFoundError",
        ),
    )

    result = runner.run_process(
        SandboxConfig(
            tool_name="shell.exec",
            command=["echo", "ok"],
            containment_profile=ContainmentProfile.SUPPORTED,
        ),
        backend=backend,
        command=["echo", "ok"],
        env={},
        connect_path_allowed_ips=[],
        enforce_connect_path=False,
    )

    assert result.blocked_reason == "runtime_isolation_unavailable"
    assert result.isolation_degraded is True


def test_m6_process_to_text_helpers() -> None:
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
