"""M4.T26 connect-path degraded signaling coverage."""

from __future__ import annotations

import sys

import pytest

from shisad.executors.connect_path import (
    ConnectPathResult,
    IptablesConnectPathProxy,
    NoopConnectPathProxy,
)
from shisad.executors.proxy import EgressProxy, NetworkPolicy
from shisad.executors.sandbox import (
    DegradedModePolicy,
    SandboxBackend,
    SandboxConfig,
    SandboxEnforcement,
    SandboxOrchestrator,
    SandboxType,
)


def _resolver(_hostname: str) -> list[str]:
    return ["93.184.216.34"]


def test_m4_t26_connect_path_degraded_signal_emitted_when_unavailable() -> None:
    orchestrator = SandboxOrchestrator(
        proxy=EgressProxy(resolver=_resolver),
        connect_path_proxy=NoopConnectPathProxy(net_admin_available=False),
    )
    orchestrator._backends[SandboxType.CONTAINER] = SandboxBackend(
        backend=SandboxType.CONTAINER,
        runtime="",
        enforcement=SandboxEnforcement(
            filesystem=True,
            network=True,
            env=True,
            seccomp=True,
            resource_limits=True,
            cgroups=False,
            dns_control=True,
        ),
    )
    result = orchestrator.execute(
        SandboxConfig(
            tool_name="http_request",
            command=[sys.executable, "-c", "print('ok')"],
            sandbox_type=SandboxType.CONTAINER,
            network=NetworkPolicy(allow_network=True, allowed_domains=["api.good.com"]),
            network_urls=["https://api.good.com/v1"],
            degraded_mode=DegradedModePolicy.FAIL_OPEN,
            security_critical=False,
        )
    )
    assert result.allowed is True
    assert "connect_path" in result.degraded_controls


class _CaptureConnectPathProxy:
    net_admin_available = True

    def __init__(self) -> None:
        self.namespace_pids: list[int] = []

    def enforce(self, *, allowed_ips: list[str], namespace_pid: int) -> ConnectPathResult:
        _ = allowed_ips
        self.namespace_pids.append(namespace_pid)
        return ConnectPathResult(enforced=True, method="iptables", reason="enforced")


def test_m5_rt12_connect_path_uses_runtime_process_pid() -> None:
    proxy = _CaptureConnectPathProxy()
    orchestrator = SandboxOrchestrator(
        proxy=EgressProxy(resolver=_resolver),
        connect_path_proxy=proxy,
    )
    orchestrator._backends[SandboxType.CONTAINER] = SandboxBackend(
        backend=SandboxType.CONTAINER,
        runtime="",
        enforcement=SandboxEnforcement(
            filesystem=True,
            network=True,
            env=True,
            seccomp=True,
            resource_limits=True,
            cgroups=False,
            dns_control=True,
        ),
    )
    result = orchestrator.execute(
        SandboxConfig(
            tool_name="http_request",
            command=[sys.executable, "-c", "print('ok')"],
            sandbox_type=SandboxType.CONTAINER,
            network=NetworkPolicy(allow_network=True, allowed_domains=["api.good.com"]),
            network_urls=["https://api.good.com/v1"],
            degraded_mode=DegradedModePolicy.FAIL_OPEN,
            security_critical=False,
        )
    )
    assert result.allowed is True
    assert proxy.namespace_pids
    assert all(pid > 0 for pid in proxy.namespace_pids)


def test_m5_rt13_connect_path_refuses_host_namespace(monkeypatch) -> None:
    proxy = IptablesConnectPathProxy(net_admin_available=True)
    proxy._iptables = "/usr/sbin/iptables"
    proxy._nsenter = "/usr/bin/nsenter"
    calls: list[list[str]] = []

    def _fake_run(namespace_pid: int, args: list[str]) -> None:
        _ = namespace_pid
        calls.append(list(args))

    monkeypatch.setattr(proxy, "_is_isolated_namespace", lambda namespace_pid: False)
    monkeypatch.setattr(proxy, "_run", _fake_run)

    result = proxy.enforce(allowed_ips=["93.184.216.34"], namespace_pid=1234)
    assert result.enforced is False
    assert result.reason == "host_namespace_unsafe"
    assert calls == []


def test_m6_connect_path_guard_branches_for_invalid_pid_and_empty_ips() -> None:
    proxy = IptablesConnectPathProxy(net_admin_available=True)
    proxy._iptables = "/usr/sbin/iptables"
    proxy._nsenter = "/usr/bin/nsenter"
    assert (
        proxy.enforce(allowed_ips=["93.184.216.34"], namespace_pid=0).reason
        == "invalid_namespace_pid"
    )
    proxy._is_isolated_namespace = lambda _pid: True  # type: ignore[method-assign]
    assert proxy.enforce(allowed_ips=[], namespace_pid=1234).reason == "empty_allowed_ips"


def test_m6_connect_path_reports_iptables_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    proxy = IptablesConnectPathProxy(net_admin_available=True)
    proxy._iptables = "/usr/sbin/iptables"
    proxy._nsenter = "/usr/bin/nsenter"
    monkeypatch.setattr(proxy, "_is_isolated_namespace", lambda namespace_pid: True)
    monkeypatch.setattr(
        proxy,
        "_run",
        lambda namespace_pid, args: (_ for _ in ()).throw(RuntimeError("boom")),
    )
    result = proxy.enforce(allowed_ips=["93.184.216.34"], namespace_pid=1234)
    assert result.enforced is False
    assert result.reason == "iptables_failed:RuntimeError"


def test_m6_connect_path_success_enforcement_runs_expected_rules(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    proxy = IptablesConnectPathProxy(net_admin_available=True)
    proxy._iptables = "/usr/sbin/iptables"
    proxy._nsenter = "/usr/bin/nsenter"
    monkeypatch.setattr(proxy, "_is_isolated_namespace", lambda namespace_pid: True)
    calls: list[list[str]] = []
    monkeypatch.setattr(proxy, "_run", lambda namespace_pid, args: calls.append(list(args)))
    result = proxy.enforce(allowed_ips=["93.184.216.34", "93.184.216.34"], namespace_pid=1234)
    assert result.enforced is True
    assert result.reason == "enforced"
    assert calls[0] == ["-F", "OUTPUT"]
    assert calls[-1] == ["-A", "OUTPUT", "-j", "DROP"]


def test_m6_connect_path_detect_capability_branches(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("os.geteuid", lambda: 0)
    monkeypatch.setattr(
        "shisad.executors.connect_path.shutil.which",
        lambda name: "/usr/sbin/iptables",
    )
    assert IptablesConnectPathProxy.detect_net_admin_capability() is True

    monkeypatch.setattr("os.geteuid", lambda: 1000)
    monkeypatch.setattr(
        "shisad.executors.connect_path.shutil.which",
        lambda name: "/usr/bin/capsh" if name == "capsh" else "",
    )
    monkeypatch.setattr(
        "subprocess.run",
        lambda *args, **kwargs: (_ for _ in ()).throw(OSError("no capsh")),
    )
    assert IptablesConnectPathProxy.detect_net_admin_capability() is False

    monkeypatch.setattr(
        "subprocess.run",
        lambda *args, **kwargs: type("Result", (), {"stdout": "cap_net_admin+ep", "stderr": ""})(),
    )
    assert IptablesConnectPathProxy.detect_net_admin_capability() is True
