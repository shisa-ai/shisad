"""Policy lint checks for egress host-pattern breadth constraints."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from shisad.security.policy import PolicyBundle


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
