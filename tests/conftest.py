"""Shared pytest configuration for milestone-specific markers."""

from __future__ import annotations

import pytest

from shisad.executors.connect_path import IptablesConnectPathProxy
from tests.helpers.daemon import clear_channel_env


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        "requires_cap_net_admin: test requires CAP_NET_ADMIN for privileged connect-path checks",
    )
    config.addinivalue_line(
        "markers",
        (
            "allow_channel_env: test opts into ambient SHISAD_MATRIX_* / "
            "SHISAD_DISCORD_* / SHISAD_TELEGRAM_* / SHISAD_SLACK_* "
            "environment variables"
        ),
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


@pytest.fixture(autouse=True)
def _scrub_channel_env_for_hermetic_tests(
    monkeypatch: pytest.MonkeyPatch,
    request: pytest.FixtureRequest,
) -> None:
    """Default-off channel env for hermetic tests unless explicitly opted in."""
    if request.node.get_closest_marker("allow_channel_env") is not None:
        return

    clear_channel_env(monkeypatch)
