"""M0.T4-T5: PEP rejects unknown tools and invalid schemas."""

from __future__ import annotations

from shisad.core.tools.registry import ToolRegistry
from shisad.core.tools.schema import ToolDefinition, ToolParameter
from shisad.core.types import Capability, PEPDecisionKind, ToolName
from shisad.security.pep import PEP, PolicyContext
from shisad.security.policy import PolicyBundle, ToolPolicy


def _make_pep() -> tuple[PEP, ToolRegistry]:
    """Create a PEP with a simple tool registered."""
    registry = ToolRegistry()
    registry.register(
        ToolDefinition(
            name=ToolName("test_tool"),
            description="A test tool",
            parameters=[
                ToolParameter(name="query", type="string", required=True),
                ToolParameter(name="limit", type="integer", required=False),
            ],
            capabilities_required=[Capability.HTTP_REQUEST],
        )
    )
    policy = PolicyBundle(default_require_confirmation=False)
    return PEP(policy, registry), registry


class TestPepRejectsUnknownTools:
    """M0.T4: PEP rejects unknown tools."""

    def test_unknown_tool_rejected(self) -> None:
        pep, _ = _make_pep()
        ctx = PolicyContext(capabilities={Capability.HTTP_REQUEST})
        decision = pep.evaluate(ToolName("nonexistent"), {}, ctx)
        assert decision.kind == PEPDecisionKind.REJECT
        assert "Unknown tool" in decision.reason

    def test_known_tool_allowed(self) -> None:
        pep, _ = _make_pep()
        ctx = PolicyContext(capabilities={Capability.HTTP_REQUEST})
        decision = pep.evaluate(ToolName("test_tool"), {"query": "hello"}, ctx)
        assert decision.kind == PEPDecisionKind.ALLOW


class TestPepSchemaValidation:
    """M0.T5: PEP rejects invalid tool argument schemas."""

    def test_missing_required_arg_rejected(self) -> None:
        pep, _ = _make_pep()
        ctx = PolicyContext(capabilities={Capability.HTTP_REQUEST})
        decision = pep.evaluate(ToolName("test_tool"), {}, ctx)
        assert decision.kind == PEPDecisionKind.REJECT
        assert "Missing required" in decision.reason

    def test_extra_arg_rejected(self) -> None:
        pep, _ = _make_pep()
        ctx = PolicyContext(capabilities={Capability.HTTP_REQUEST})
        decision = pep.evaluate(
            ToolName("test_tool"), {"query": "hello", "unknown": "bad"}, ctx
        )
        assert decision.kind == PEPDecisionKind.REJECT
        assert "Unexpected argument" in decision.reason

    def test_wrong_type_rejected(self) -> None:
        pep, _ = _make_pep()
        ctx = PolicyContext(capabilities={Capability.HTTP_REQUEST})
        decision = pep.evaluate(
            ToolName("test_tool"), {"query": "hello", "limit": "not_an_int"}, ctx
        )
        assert decision.kind == PEPDecisionKind.REJECT
        assert "expected type" in decision.reason

    def test_missing_capability_rejected(self) -> None:
        pep, _ = _make_pep()
        ctx = PolicyContext(capabilities=set())  # No capabilities
        decision = pep.evaluate(ToolName("test_tool"), {"query": "hello"}, ctx)
        assert decision.kind == PEPDecisionKind.REJECT
        assert "Missing capabilities" in decision.reason


class TestPepToolAllowlist:
    """M0.7.3: tool allowlist checks."""

    def test_context_tool_allowlist_rejects_not_allowed_tool(self) -> None:
        pep, _ = _make_pep()
        ctx = PolicyContext(
            capabilities={Capability.HTTP_REQUEST},
            tool_allowlist={ToolName("different_tool")},
        )
        decision = pep.evaluate(ToolName("test_tool"), {"query": "hello"}, ctx)
        assert decision.kind == PEPDecisionKind.REJECT
        assert "allowlist" in decision.reason.lower()


class TestPepAllowedArgsPolicy:
    """Policy-level allowed_args constraints."""

    def test_allowed_args_policy_blocks_unapproved_argument_values(self) -> None:
        registry = ToolRegistry()
        registry.register(
            ToolDefinition(
                name=ToolName("test_tool"),
                description="A test tool",
                parameters=[ToolParameter(name="query", type="string", required=True)],
                capabilities_required=[Capability.HTTP_REQUEST],
            )
        )
        policy = PolicyBundle(
            default_require_confirmation=False,
            tools={
                ToolName("test_tool"): ToolPolicy(
                    capabilities_required=[Capability.HTTP_REQUEST],
                    require_confirmation=False,
                    allowed_args={"query": "approved"},
                )
            },
        )
        pep = PEP(policy, registry)
        ctx = PolicyContext(capabilities={Capability.HTTP_REQUEST})

        allowed = pep.evaluate(ToolName("test_tool"), {"query": "approved"}, ctx)
        assert allowed.kind == PEPDecisionKind.ALLOW

        blocked = pep.evaluate(ToolName("test_tool"), {"query": "something_else"}, ctx)
        assert blocked.kind == PEPDecisionKind.REJECT
        assert "allowed_args" in blocked.reason

    def test_policy_tool_allowlist_rejects_unlisted_tool(self) -> None:
        registry = ToolRegistry()
        registry.register(
            ToolDefinition(
                name=ToolName("test_tool"),
                description="A test tool",
                parameters=[ToolParameter(name="query", type="string", required=True)],
                capabilities_required=[Capability.HTTP_REQUEST],
            )
        )
        policy = PolicyBundle(
            default_require_confirmation=False,
            tools={
                ToolName("other_tool"): ToolPolicy(
                    capabilities_required=[],
                    require_confirmation=False,
                )
            },
        )
        pep = PEP(policy, registry)
        ctx = PolicyContext(capabilities={Capability.HTTP_REQUEST})
        decision = pep.evaluate(ToolName("test_tool"), {"query": "hello"}, ctx)
        assert decision.kind == PEPDecisionKind.REJECT
        assert "allowlist" in decision.reason.lower()
