"""Host matcher and credential allowlist regression coverage."""

from __future__ import annotations

from shisad.core.host_matching import host_matches
from shisad.core.types import CredentialRef
from shisad.security.credentials import CredentialConfig, InMemoryCredentialStore


def test_m1_pf44_host_matches_exact_rule() -> None:
    assert host_matches("api.example.com", "api.example.com")
    assert not host_matches("api.example.com", "example.com")


def test_m1_pf44_host_matches_suffix_rule() -> None:
    assert host_matches("api.example.com", "*.example.com")
    assert not host_matches("example.org", "*.example.com")


def test_m1_pf44_host_matches_wildcard_rule() -> None:
    assert host_matches("api.example.com", "*")


def test_m1_pf44_host_matches_suffix_rule_does_not_match_apex() -> None:
    assert not host_matches("example.com", "*.example.com")


def test_m1_pf44_host_matches_suffix_rule_tld_breadth_is_explicit() -> None:
    assert host_matches("evil.com", "*.com")


def test_m1_pf44_host_matches_rejects_host_with_port_string() -> None:
    assert not host_matches("example.com:443", "example.com")


def test_m1_pf44_host_matches_case_insensitively() -> None:
    assert host_matches("API.Example.Com", "*.example.com")


def test_m1_pf44_credential_store_uses_shared_host_matcher() -> None:
    store = InMemoryCredentialStore()
    store.register(
        CredentialRef("api.token"),
        "secret-value",
        CredentialConfig(allowed_hosts=["*.example.com"]),
    )
    placeholder = store.get_placeholder(CredentialRef("api.token"))
    assert store.resolve(placeholder, "Service.EXAMPLE.com") == "secret-value"
