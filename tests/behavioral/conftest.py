"""Shared fixtures for behavioral tests.

Behavioral tests validate the product contract: can the user do X?
They use the control plane directly (no live daemon) with specific
capability sets to verify that authorized actions are not blocked.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from shisad.core.types import Capability
from shisad.security.control_plane.engine import ControlPlaneEngine
from shisad.security.control_plane.schema import Origin


@pytest.fixture
def cp_engine(tmp_path: Path) -> ControlPlaneEngine:
    """Build a control plane engine with default configuration."""
    return ControlPlaneEngine.build(
        data_dir=tmp_path / "control_plane",
        monitor_timeout_seconds=0.5,
        monitor_cache_ttl_seconds=300,
        baseline_learning_rate=0.1,
        trace_ttl_seconds=600,
        trace_max_actions=10,
    )


@pytest.fixture
def all_capabilities() -> set[Capability]:
    """All defined capabilities — the default session grant."""
    return set(Capability)


@pytest.fixture
def planner_origin() -> Origin:
    return Origin(
        session_id="test-session",
        user_id="test-user",
        workspace_id="test-ws",
        actor="planner",
        trust_level="untrusted",
    )
