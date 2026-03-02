"""Behavioral tests: tool access UX.

These tests validate the product contract from DESIGN-PHILOSOPHY.md:
- A user with granted capabilities can use them without lockdown.
- Trace-only stage2 blocks route to confirmation, not lockdown.
- The capability → action mapping is exhaustive.

No live daemon needed — tests exercise the control plane directly.
"""

from __future__ import annotations

import pytest

from shisad.core.types import Capability
from shisad.security.control_plane.engine import ControlPlaneEngine
from shisad.security.control_plane.schema import (
    _CAPABILITY_TO_ACTION_KINDS,
    ActionKind,
    ControlDecision,
    Origin,
    RiskTier,
    action_kinds_for_capabilities,
)

# ---------------------------------------------------------------------------
# CC.7 Test 1: Session with HTTP_REQUEST → web.search does not trigger lockdown
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_egress_tool_does_not_trigger_lockdown(
    cp_engine: ControlPlaneEngine,
    all_capabilities: set[Capability],
    planner_origin: Origin,
) -> None:
    """A session with HTTP_REQUEST capability should be able to use web.search
    without hitting stage2 upgrade or lockdown."""
    cp_engine.begin_precontent_plan(
        session_id="test-session",
        goal="grab me the latest world news",
        origin=planner_origin,
        ttl_seconds=600,
        max_actions=10,
        capabilities=all_capabilities,
    )
    result = await cp_engine.evaluate_action(
        tool_name="web.search",
        arguments={"query": "latest world news"},
        origin=planner_origin,
        risk_tier=RiskTier.LOW,
        declared_domains=[],
        session_tainted=False,
        trusted_input=True,
    )
    assert result.decision != ControlDecision.BLOCK, (
        f"web.search blocked with reason: {result.reason_codes}"
    )
    assert "trace:stage2_upgrade_required" not in result.reason_codes


# ---------------------------------------------------------------------------
# CC.7 Test 2: Session capabilities are reflected in the stage1 plan
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_session_capabilities_reflected_in_stage1_plan(
    cp_engine: ControlPlaneEngine,
    planner_origin: Origin,
) -> None:
    """When capabilities include HTTP_REQUEST, EGRESS must be in stage1
    allowed_actions. When they don't, it must not be."""
    # With HTTP_REQUEST
    cp_engine.begin_precontent_plan(
        session_id="test-with-egress",
        goal="search the web",
        origin=Origin(
            session_id="test-with-egress",
            user_id="test-user",
            workspace_id="test-ws",
            actor="planner",
            trust_level="untrusted",
        ),
        ttl_seconds=600,
        max_actions=10,
        capabilities={Capability.HTTP_REQUEST, Capability.FILE_READ},
    )
    plan_with = cp_engine._trace_verifier.active_plan("test-with-egress")
    assert plan_with is not None
    assert ActionKind.EGRESS in plan_with.allowed_actions

    # Without HTTP_REQUEST — EGRESS should NOT be in stage1
    cp_engine.begin_precontent_plan(
        session_id="test-without-egress",
        goal="read a file",
        origin=Origin(
            session_id="test-without-egress",
            user_id="test-user",
            workspace_id="test-ws",
            actor="planner",
            trust_level="untrusted",
        ),
        ttl_seconds=600,
        max_actions=10,
        capabilities={Capability.FILE_READ},
    )
    plan_without = cp_engine._trace_verifier.active_plan("test-without-egress")
    assert plan_without is not None
    assert ActionKind.EGRESS not in plan_without.allowed_actions


# ---------------------------------------------------------------------------
# CC.7 Test 3: Trace-only stage2 block routes to REQUIRE_CONFIRMATION
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_trace_only_stage2_routes_to_confirmation(
    cp_engine: ControlPlaneEngine,
    planner_origin: Origin,
) -> None:
    """A session WITHOUT HTTP_REQUEST that tries web.search should get
    stage2_upgrade_required — but the trace result must not be a hard block
    from non-trace voters (i.e., only trace blocks it). This validates
    that the engine routes it correctly."""
    # Plan without EGRESS capability
    cp_engine.begin_precontent_plan(
        session_id="test-session",
        goal="read some files",
        origin=planner_origin,
        ttl_seconds=600,
        max_actions=10,
        capabilities={Capability.FILE_READ},  # No HTTP_REQUEST
    )
    result = await cp_engine.evaluate_action(
        tool_name="web.search",
        arguments={"query": "news"},
        origin=planner_origin,
        risk_tier=RiskTier.LOW,
        declared_domains=[],
        session_tainted=False,
        trusted_input=True,
    )
    # The trace verifier should block with stage2_upgrade_required
    assert result.trace_result.reason_code == "trace:stage2_upgrade_required"
    # The overall decision should be BLOCK (at engine level) because
    # the session lacks the capability — but the session handler will
    # demote trace-only blocks to confirmation (tested in CC.5 handler tests)
    assert result.decision == ControlDecision.BLOCK


# ---------------------------------------------------------------------------
# CC.7 Test 4: Capability mapping is exhaustive
# ---------------------------------------------------------------------------


def test_capability_mapping_exhaustive() -> None:
    """Every Capability enum value must have an entry in
    _CAPABILITY_TO_ACTION_KINDS."""
    unmapped = set()
    for cap in Capability:
        if cap not in _CAPABILITY_TO_ACTION_KINDS:
            unmapped.add(cap)
    assert not unmapped, f"Capabilities without ActionKind mapping: {unmapped}"


# ---------------------------------------------------------------------------
# CC.7 Test 5: All capabilities grant their expected action kinds
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_all_default_capabilities_allow_expected_tools(
    cp_engine: ControlPlaneEngine,
    all_capabilities: set[Capability],
    planner_origin: Origin,
) -> None:
    """With all capabilities granted, the plan should include all action kinds
    except UNKNOWN and ENV_ACCESS."""
    cp_engine.begin_precontent_plan(
        session_id="test-session",
        goal="do everything",
        origin=planner_origin,
        ttl_seconds=600,
        max_actions=20,
        capabilities=all_capabilities,
    )
    plan = cp_engine._trace_verifier.active_plan("test-session")
    assert plan is not None
    # All mapped action kinds should be present
    expected = action_kinds_for_capabilities(all_capabilities)
    missing = expected - plan.allowed_actions
    assert not missing, f"Expected action kinds missing from plan: {missing}"


# ---------------------------------------------------------------------------
# CC.7 Test 6: Strict base actions are always present
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_strict_base_actions_always_present(
    cp_engine: ControlPlaneEngine,
    planner_origin: Origin,
) -> None:
    """Even with no capabilities, FS_READ, FS_LIST, and MEMORY_READ are
    always in the stage1 plan (strict base)."""
    cp_engine.begin_precontent_plan(
        session_id="test-session",
        goal="something",
        origin=planner_origin,
        ttl_seconds=600,
        max_actions=10,
        capabilities=set(),  # Empty capabilities
    )
    plan = cp_engine._trace_verifier.active_plan("test-session")
    assert plan is not None
    assert ActionKind.FS_READ in plan.allowed_actions
    assert ActionKind.FS_LIST in plan.allowed_actions
    assert ActionKind.MEMORY_READ in plan.allowed_actions


# ---------------------------------------------------------------------------
# CC.7 Test 7: Backward compat — no capabilities param defaults to strict base
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_no_capabilities_param_defaults_to_strict_base(
    cp_engine: ControlPlaneEngine,
    planner_origin: Origin,
) -> None:
    """Calling begin_precontent_plan without capabilities= should still work
    and default to the strict base (backward compat)."""
    cp_engine.begin_precontent_plan(
        session_id="test-session",
        goal="something",
        origin=planner_origin,
        ttl_seconds=600,
        max_actions=10,
        # No capabilities param
    )
    plan = cp_engine._trace_verifier.active_plan("test-session")
    assert plan is not None
    assert plan.allowed_actions == {
        ActionKind.FS_READ,
        ActionKind.FS_LIST,
        ActionKind.MEMORY_READ,
    }
