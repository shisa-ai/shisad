"""Shared pytest configuration for milestone-specific markers."""

from __future__ import annotations

import pytest

from shisad.executors.connect_path import IptablesConnectPathProxy


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        "requires_cap_net_admin: test requires CAP_NET_ADMIN for privileged connect-path checks",
    )


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    _ = config
    has_cap = IptablesConnectPathProxy.detect_net_admin_capability()
    if has_cap:
        return
    skip = pytest.mark.skip(reason="requires CAP_NET_ADMIN capability (unavailable)")
    for item in items:
        if "requires_cap_net_admin" in item.keywords:
            item.add_marker(skip)
