"""Shared fixtures for behavioral tests.

Behavioral tests validate the product contract: can the user do X?
They use the control plane directly (no live daemon) with specific
capability sets to verify that authorized actions are not blocked.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import pytest

from shisad.core.types import Capability
from shisad.security.control_plane.engine import ControlPlaneEngine
from shisad.security.control_plane.schema import Origin
from tests.behavioral._prefill import prefill_accumulated_tool_output
from tests.behavioral.test_behavioral_contract import (
    ContractHarness,
    _contract_harness_context,
)


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


@pytest.fixture
def contract_harness_factory(
    tmp_path_factory: pytest.TempPathFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> Any:
    @asynccontextmanager
    async def _factory(
        *,
        name: str = "contract-harness",
        prestart: Any = None,
        default_require_confirmation: bool = False,
        web_search_backend_configured: bool = True,
        policy_egress_allowed: bool = True,
        browser_enabled: bool | None = None,
    ) -> AsyncIterator[ContractHarness]:
        tmp_path = tmp_path_factory.mktemp(name)
        async with _contract_harness_context(
            tmp_path,
            monkeypatch,
            prestart=prestart,
            default_require_confirmation=default_require_confirmation,
            web_search_backend_configured=web_search_backend_configured,
            policy_egress_allowed=policy_egress_allowed,
            browser_enabled=browser_enabled,
        ) as harness:
            yield harness

    return _factory


@pytest.fixture
async def accumulated_state_harness(contract_harness_factory: Any) -> ContractHarness:
    async with contract_harness_factory(
        name="accumulated-state",
        prestart=prefill_accumulated_tool_output,
    ) as harness:
        yield harness


@pytest.fixture
async def clean_harness(contract_harness_factory: Any) -> ContractHarness:
    async with contract_harness_factory(name="clean") as harness:
        yield harness


@pytest.fixture
async def cross_session_harness(contract_harness_factory: Any) -> ContractHarness:
    async with contract_harness_factory(name="cross-session") as harness:
        yield harness


@pytest.fixture
async def degraded_runtime_harness(contract_harness_factory: Any) -> ContractHarness:
    async with contract_harness_factory(
        name="degraded-runtime",
        web_search_backend_configured=False,
        policy_egress_allowed=False,
    ) as harness:
        yield harness


@pytest.fixture
async def confirmation_followup_harness(contract_harness_factory: Any) -> ContractHarness:
    async with contract_harness_factory(name="confirmation-followup") as harness:
        (harness.workspace_root / "todo.log").write_text(
            "OPEN: verify confirmed result threading\n",
            encoding="utf-8",
        )
        yield harness


@pytest.fixture
async def require_confirmation_harness(contract_harness_factory: Any) -> ContractHarness:
    async with contract_harness_factory(
        name="require-confirmation",
        default_require_confirmation=True,
    ) as harness:
        yield harness
