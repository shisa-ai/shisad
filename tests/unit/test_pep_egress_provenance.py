"""Unit checks for provenance-aware egress decisions in the PEP."""

from __future__ import annotations

from shisad.core.tools.registry import ToolRegistry
from shisad.core.tools.schema import ToolDefinition, ToolParameter
from shisad.core.types import Capability, PEPDecisionKind, ToolName
from shisad.security.pep import PEP, PolicyContext
from shisad.security.policy import EgressRule, PolicyBundle


def _registry_with_web_fetch() -> ToolRegistry:
    registry = ToolRegistry()
    registry.register(
        ToolDefinition(
            name=ToolName("web.fetch"),
            description="Fetch URL with structured evidence payload.",
            parameters=[
                ToolParameter(name="url", type="string", required=True),
                ToolParameter(name="snapshot", type="boolean", required=False),
                ToolParameter(name="max_bytes", type="integer", required=False),
            ],
            capabilities_required=[Capability.HTTP_REQUEST],
            require_confirmation=False,
        )
    )
    return registry


def _registry_with_web_search(destination: str) -> ToolRegistry:
    registry = ToolRegistry()
    registry.register(
        ToolDefinition(
            name=ToolName("web.search"),
            description="Search via configured backend (SearxNG reference in v0.3).",
            parameters=[
                ToolParameter(name="query", type="string", required=True),
                ToolParameter(name="limit", type="integer", required=False),
            ],
            capabilities_required=[Capability.HTTP_REQUEST],
            destinations=[destination],
            require_confirmation=False,
        )
    )
    return registry


def test_pep_allows_user_goal_destination_without_allowlist() -> None:
    pep = PEP(PolicyBundle(), _registry_with_web_fetch())
    context = PolicyContext(
        capabilities={Capability.HTTP_REQUEST},
        user_goal_host_patterns={"nytimes.com", "*.nytimes.com"},
        trust_level="trusted",
    )
    decision = pep.evaluate(
        ToolName("web.fetch"),
        {"url": "https://www.nytimes.com/"},
        context,
    )
    assert decision.kind == PEPDecisionKind.ALLOW


def test_pep_allows_tool_declared_destination_without_allowlist_or_user_goal() -> None:
    pep = PEP(PolicyBundle(), _registry_with_web_search("https://search.example.com"))
    context = PolicyContext(
        capabilities={Capability.HTTP_REQUEST},
        trust_level="trusted",
    )
    decision = pep.evaluate(
        ToolName("web.search"),
        {"query": "latest news", "limit": 3},
        context,
    )
    assert decision.kind == PEPDecisionKind.ALLOW


def test_pep_allows_tool_declared_local_destination_without_allowlist() -> None:
    pep = PEP(PolicyBundle(), _registry_with_web_search("http://localhost:8080"))
    context = PolicyContext(
        capabilities={Capability.HTTP_REQUEST},
        trust_level="trusted",
    )
    decision = pep.evaluate(
        ToolName("web.search"),
        {"query": "latest news", "limit": 3},
        context,
    )
    assert decision.kind == PEPDecisionKind.ALLOW


def test_pep_requires_confirmation_for_untrusted_suggested_destination() -> None:
    pep = PEP(PolicyBundle(), _registry_with_web_fetch())
    context = PolicyContext(
        capabilities={Capability.HTTP_REQUEST},
        untrusted_host_patterns={"example.com", "*.example.com"},
        trust_level="trusted",
    )
    decision = pep.evaluate(
        ToolName("web.fetch"),
        {"url": "https://example.com/"},
        context,
    )
    assert decision.kind == PEPDecisionKind.REQUIRE_CONFIRMATION


def test_pep_rejects_unattributed_unknown_destination() -> None:
    pep = PEP(PolicyBundle(), _registry_with_web_fetch())
    context = PolicyContext(
        capabilities={Capability.HTTP_REQUEST},
        trust_level="trusted",
    )
    decision = pep.evaluate(
        ToolName("web.fetch"),
        {"url": "https://example.com/"},
        context,
    )
    assert decision.kind == PEPDecisionKind.REJECT


def test_pep_blocks_ip_literal_without_operator_allowlist_even_if_user_goal() -> None:
    pep = PEP(PolicyBundle(), _registry_with_web_fetch())
    context = PolicyContext(
        capabilities={Capability.HTTP_REQUEST},
        user_goal_host_patterns={"127.0.0.1"},
        trust_level="trusted",
    )
    decision = pep.evaluate(
        ToolName("web.fetch"),
        {"url": "http://127.0.0.1:80/"},
        context,
    )
    assert decision.kind == PEPDecisionKind.REJECT


def test_pep_allows_operator_allowlisted_ip_literal() -> None:
    policy = PolicyBundle(
        egress=[EgressRule(host="127.0.0.1", ports=[80], protocols=["http"])],
    )
    pep = PEP(policy, _registry_with_web_fetch())
    context = PolicyContext(
        capabilities={Capability.HTTP_REQUEST},
        trust_level="trusted",
    )
    decision = pep.evaluate(
        ToolName("web.fetch"),
        {"url": "http://127.0.0.1:80/"},
        context,
    )
    assert decision.kind == PEPDecisionKind.ALLOW
