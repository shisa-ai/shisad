"""M3 network component extraction coverage."""

from __future__ import annotations

import sys

from shisad.core.types import CredentialRef
from shisad.executors.connect_path import IptablesConnectPathProxy, NoopConnectPathProxy
from shisad.executors.proxy import EgressProxy, NetworkPolicy
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
