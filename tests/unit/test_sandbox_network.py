"""M3 network component extraction coverage."""

from __future__ import annotations

import sys

from shisad.core.types import CredentialRef
from shisad.executors.proxy import EgressProxy, NetworkPolicy
from shisad.executors.sandbox import SandboxNetworkManager
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
