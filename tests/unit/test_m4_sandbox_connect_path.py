"""M4.T26 connect-path degraded signaling coverage."""

from __future__ import annotations

import sys

from shisad.executors.connect_path import NoopConnectPathProxy
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
