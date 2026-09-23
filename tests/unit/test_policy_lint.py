"""Policy lint checks for egress host-pattern breadth constraints."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from shisad.security.policy import PolicyBundle


@pytest.mark.parametrize(
    "policy",
    [
        {"skills": {"trusted_key_ids": ["org-main"]}},
        {"control_plane": {"network": {"ingress_metadata_scope": "all"}}},
    ],
)
def test_unsupported_policy_fields_are_rejected(policy: dict[str, object]) -> None:
    with pytest.raises(ValidationError, match="unsupported"):
        PolicyBundle.model_validate(policy)


def test_m5_cf_v0353_rejects_global_wildcard_egress_host_pattern() -> None:
    with pytest.raises(
        ValidationError,
        match=r"Egress host pattern '\*' is too broad",
    ):
        PolicyBundle.model_validate({"egress": [{"host": "*"}]})


def test_m5_cf_v0353_rejects_tld_wildcard_egress_host_pattern() -> None:
    with pytest.raises(
        ValidationError,
        match=r"Egress host pattern '\*\.com' is too broad",
    ):
        PolicyBundle.model_validate({"egress": [{"host": "*.com"}]})


def test_m5_cf_v0353_allows_subdomain_wildcard_with_domain_depth() -> None:
    bundle = PolicyBundle.model_validate({"egress": [{"host": "*.example.com"}]})
    assert bundle.egress[0].host == "*.example.com"


@pytest.mark.parametrize(
    "host",
    [
        "https://api.example.com",
        "api.example.com:443",
        "example.com/path",
        "user@example.com",
        "[::1]:443",
        "[broken:address]",
        "bad host",
        "bad%host",
    ],
)
def test_egress_host_rejects_url_or_port(host: str) -> None:
    with pytest.raises(ValidationError, match="bare host"):
        PolicyBundle.model_validate({"egress": [{"host": host}]})


@pytest.mark.parametrize("host", ["api.example.com", "*.example.com", "127.0.0.1", "[::1]", "::1"])
def test_egress_host_accepts_host_patterns_and_ip_literals(host: str) -> None:
    bundle = PolicyBundle.model_validate({"egress": [{"host": host}]})
    assert bundle.egress[0].host == host
