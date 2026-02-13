"""M3 network component extraction coverage."""

from __future__ import annotations

import sys

from shisad.core.types import CredentialRef
from shisad.executors.connect_path import IptablesConnectPathProxy, NoopConnectPathProxy
from shisad.executors.proxy import EgressProxy, NetworkPolicy, ProxyDecision
from shisad.executors.sandbox import SandboxNetworkManager, SandboxOrchestrator
from shisad.security.credentials import CredentialConfig, InMemoryCredentialStore


def _resolver(_hostname: str) -> list[str]:
    return ["93.184.216.34"]


def test_m3_network_extract_targets_and_detect_network_commands() -> None:
    manager = SandboxNetworkManager(EgressProxy(resolver=_resolver))
    targets = manager.extract_network_targets(
        [sys.executable, "-c", "print('ok')", "https://api.good.com/v1", "api.backup.com"]
    )
    assert targets == ["https://api.good.com/v1", "https://api.backup.com/"]
    assert manager.command_attempts_network(["curl", "https://api.good.com/v1"]) is True
    assert manager.command_attempts_network([sys.executable, "-c", "print('ok')"]) is False


def test_m3_network_authorize_requests_fail_closed_on_unallowlisted_host() -> None:
    manager = SandboxNetworkManager(EgressProxy(resolver=_resolver))
    decisions, reason = manager.authorize_requests(
        tool_name="http_request",
        urls=["https://evil.com/collect"],
        policy=NetworkPolicy(allow_network=True, allowed_domains=["api.good.com"]),
        request_headers={},
        request_body="",
        approved_by_pep=False,
    )
    assert len(decisions) == 1
    assert decisions[0].allowed is False
    assert reason == "host_not_allowlisted"


def test_m3_network_inject_credentials_requires_pep_approval() -> None:
    store = InMemoryCredentialStore()
    store.register(
        CredentialRef("gmail_primary"),
        "real-secret-token",
        CredentialConfig(allowed_hosts=["api.good.com"]),
    )
    placeholder = store.get_placeholder(CredentialRef("gmail_primary"))
    manager = SandboxNetworkManager(EgressProxy(credential_store=store, resolver=_resolver))
    _, _, reason = manager.inject_credentials(
        command=[sys.executable, "-c", "print('noop')"],
        env={"AUTH": placeholder},
        network_decisions=[],
        approved_by_pep=False,
    )
    assert reason is None
    _, _, reason = manager.inject_credentials(
        command=[sys.executable, "-c", "print('noop')"],
        env={"AUTH": placeholder},
        network_decisions=[
            manager.authorize_requests(
                tool_name="http_request",
                urls=["https://api.good.com/v1"],
                policy=NetworkPolicy(allow_network=True, allowed_domains=["api.good.com"]),
                request_headers={},
                request_body="",
                approved_by_pep=True,
            )[0][0]
        ],
        approved_by_pep=False,
    )
    assert reason == "pep_not_approved"


def test_m3_network_inject_credentials_success_when_approved() -> None:
    store = InMemoryCredentialStore()
    store.register(
        CredentialRef("gmail_primary"),
        "real-secret-token",
        CredentialConfig(allowed_hosts=["api.good.com"]),
    )
    placeholder = store.get_placeholder(CredentialRef("gmail_primary"))
    manager = SandboxNetworkManager(EgressProxy(credential_store=store, resolver=_resolver))
    decisions, reason = manager.authorize_requests(
        tool_name="http_request",
        urls=["https://api.good.com/v1"],
        policy=NetworkPolicy(allow_network=True, allowed_domains=["api.good.com"]),
        request_headers={},
        request_body="",
        approved_by_pep=True,
    )
    assert reason is None
    command, env, inject_reason = manager.inject_credentials(
        command=[sys.executable, "-c", "print('noop')"],
        env={"AUTH": placeholder},
        network_decisions=decisions,
        approved_by_pep=True,
    )
    assert inject_reason is None
    assert command[0] == sys.executable
    assert env["AUTH"] == "real-secret-token"


def test_m3_network_authorize_requests_preserves_resolved_headers_for_runtime_use() -> None:
    store = InMemoryCredentialStore()
    store.register(
        CredentialRef("gmail_primary"),
        "real-secret-token",
        CredentialConfig(allowed_hosts=["api.good.com"]),
    )
    placeholder = store.get_placeholder(CredentialRef("gmail_primary"))
    manager = SandboxNetworkManager(EgressProxy(credential_store=store, resolver=_resolver))
    decisions, reason = manager.authorize_requests(
        tool_name="http_request",
        urls=["https://api.good.com/v1"],
        policy=NetworkPolicy(allow_network=True, allowed_domains=["api.good.com"]),
        request_headers={"Authorization": placeholder},
        request_body="",
        approved_by_pep=True,
    )
    assert reason is None
    assert decisions
    assert decisions[0].injected_headers["Authorization"] == "real-secret-token"


def test_m3_network_revalidate_requests_rejects_decision_length_mismatch() -> None:
    manager = SandboxNetworkManager(EgressProxy(resolver=_resolver))
    reason = manager.revalidate_requests(
        tool_name="http_request",
        urls=["https://api.good.com/v1"],
        policy=NetworkPolicy(allow_network=True, allowed_domains=["api.good.com"]),
        prior_decisions=[],
        approved_by_pep=True,
    )
    assert reason == "revalidation_decision_mismatch"


def test_m3_network_connect_path_status_reports_capability_and_method() -> None:
    noop_orchestrator = SandboxOrchestrator(
        proxy=EgressProxy(resolver=_resolver),
        connect_path_proxy=NoopConnectPathProxy(net_admin_available=True),
    )
    noop_status = noop_orchestrator.connect_path_status()
    assert noop_status["method"] == "none"
    assert noop_status["available"] is False

    iptables_orchestrator = SandboxOrchestrator(
        proxy=EgressProxy(resolver=_resolver),
        connect_path_proxy=IptablesConnectPathProxy(net_admin_available=True),
    )
    iptables_status = iptables_orchestrator.connect_path_status()
    assert iptables_status["method"] == "iptables"
    assert iptables_status["available"] is True


def test_m6_network_extract_targets_supports_flags_ftp_and_dns_tools() -> None:
    manager = SandboxNetworkManager(EgressProxy(resolver=_resolver))
    targets = manager.extract_network_targets(
        [
            "curl",
            "--url=https://api.good.com/v2",
            "endpoint=https://api.backup.com/v1",
            "ftp://legacy.good.com/resource",
            "api.good.com",
        ]
    )
    assert "https://api.good.com/v2" in targets
    assert "https://api.backup.com/v1" in targets
    assert "https://legacy.good.com/resource" in targets
    assert "https://api.good.com/" in targets

    dns_targets = manager.extract_network_targets(["nslookup", "resolver.good.com"])
    assert dns_targets == ["https://resolver.good.com/"]


def test_m6_network_command_attempts_network_detects_domain_token() -> None:
    manager = SandboxNetworkManager(EgressProxy(resolver=_resolver))
    assert manager.command_attempts_network([]) is False
    assert manager.command_attempts_network(["python", "-c", "print('ok')", "api.good.com"]) is True


def test_m6_network_revalidate_requests_propagates_revalidation_reason(monkeypatch) -> None:
    manager = SandboxNetworkManager(EgressProxy(resolver=_resolver))

    def _deny_revalidation(*args, **kwargs):  # type: ignore[no-untyped-def]
        _ = args, kwargs
        return ProxyDecision(allowed=False, reason="dns_rebinding_blocked")

    monkeypatch.setattr(manager._proxy, "authorize_request", _deny_revalidation)
    reason = manager.revalidate_requests(
        tool_name="http_request",
        urls=["https://api.good.com/v1"],
        policy=NetworkPolicy(allow_network=True, allowed_domains=["api.good.com"]),
        prior_decisions=[
            ProxyDecision(
                allowed=True,
                resolved_addresses=["93.184.216.34"],
                destination_host="api.good.com",
            )
        ],
        approved_by_pep=True,
    )
    assert reason == "dns_rebinding_blocked"


def test_m6_network_inject_credentials_embedded_and_host_mismatch() -> None:
    store = InMemoryCredentialStore()
    store.register(
        CredentialRef("service"),
        "secret-value",
        CredentialConfig(allowed_hosts=["api.good.com"]),
    )
    placeholder = store.get_placeholder(CredentialRef("service"))
    manager = SandboxNetworkManager(EgressProxy(credential_store=store, resolver=_resolver))

    command, env, reason = manager.inject_credentials(
        command=["curl", f"-HAuthorization:{placeholder}"],
        env={"AUTH": f"Bearer {placeholder}"},
        network_decisions=[ProxyDecision(allowed=True, destination_host="api.good.com")],
        approved_by_pep=True,
    )
    assert reason is None
    assert "secret-value" in command[1]
    assert env["AUTH"] == "Bearer secret-value"

    _, _, mismatch_reason = manager.inject_credentials(
        command=["curl", placeholder],
        env={},
        network_decisions=[ProxyDecision(allowed=True, destination_host="api.other.com")],
        approved_by_pep=True,
    )
    assert mismatch_reason == "credential_host_mismatch"
