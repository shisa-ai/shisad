"""M0.T9, T11-T13: Credential broker tests."""

from __future__ import annotations

import pytest

from shisad.core.tools.registry import ToolRegistry
from shisad.core.tools.schema import ToolDefinition, ToolParameter
from shisad.core.types import Capability, PEPDecisionKind, ToolName
from shisad.security.credentials import (
    CredentialConfig,
    CredentialRef,
    InMemoryCredentialStore,
    generate_placeholder,
    is_placeholder,
)
from shisad.security.pep import PEP, PolicyContext
from shisad.security.policy import PolicyBundle


class TestPepRejectsRawSecrets:
    """M0.T9: credential broker rejects raw secrets in tool args."""

    def test_rejects_openai_key(self) -> None:
        registry = ToolRegistry()
        registry.register(
            ToolDefinition(
                name=ToolName("http_call"),
                description="Make HTTP request",
                parameters=[ToolParameter(name="url", type="string")],
                capabilities_required=[Capability.HTTP_REQUEST],
            )
        )
        policy = PolicyBundle(default_require_confirmation=False)
        pep = PEP(policy, registry)
        ctx = PolicyContext(capabilities={Capability.HTTP_REQUEST})

        decision = pep.evaluate(
            ToolName("http_call"),
            {"url": "https://api.example.com", "api_key": "sk-proj-abc123def456"},
            ctx,
        )
        assert decision.kind == PEPDecisionKind.REJECT
        assert "raw secret" in decision.reason.lower() or "Unexpected argument" in decision.reason

    def test_rejects_aws_key(self) -> None:
        registry = ToolRegistry()
        registry.register(
            ToolDefinition(
                name=ToolName("aws_call"),
                description="AWS API call",
                parameters=[
                    ToolParameter(name="service", type="string"),
                    ToolParameter(name="key", type="string"),
                ],
                capabilities_required=[Capability.HTTP_REQUEST],
            )
        )
        policy = PolicyBundle(default_require_confirmation=False)
        pep = PEP(policy, registry)
        ctx = PolicyContext(capabilities={Capability.HTTP_REQUEST})

        decision = pep.evaluate(
            ToolName("aws_call"),
            {"service": "s3", "key": "AKIAIOSFODNN7EXAMPLE"},
            ctx,
        )
        assert decision.kind == PEPDecisionKind.REJECT
        assert "raw secret" in decision.reason.lower()


class TestPlaceholderGeneration:
    """M0.T11: placeholder generation is deterministic per credential_ref."""

    def test_deterministic(self) -> None:
        ref = CredentialRef("openai_api_key")
        p1 = generate_placeholder(ref)
        p2 = generate_placeholder(ref)
        assert p1 == p2

    def test_different_refs_different_placeholders(self) -> None:
        p1 = generate_placeholder(CredentialRef("key_a"))
        p2 = generate_placeholder(CredentialRef("key_b"))
        assert p1 != p2

    def test_is_placeholder(self) -> None:
        ref = CredentialRef("test")
        p = generate_placeholder(ref)
        assert is_placeholder(p)
        assert not is_placeholder("not_a_placeholder")


class TestCredentialStoreReturnsPlaceholder:
    """M0.T12: credential store returns placeholder, never raw value."""

    def test_get_placeholder_not_raw_value(self) -> None:
        store = InMemoryCredentialStore()
        ref = CredentialRef("openai_key")
        store.register(
            ref,
            "sk-real-secret-value",
            CredentialConfig(allowed_hosts=["api.openai.com"]),
        )
        placeholder = store.get_placeholder(ref)
        assert "sk-real-secret-value" not in placeholder
        assert is_placeholder(placeholder)

    def test_unknown_ref_raises(self) -> None:
        store = InMemoryCredentialStore()
        with pytest.raises(KeyError):
            store.get_placeholder(CredentialRef("nonexistent"))


class TestHostScopedBinding:
    """M0.T13: host-scoped binding rejects credential use for non-allowed host."""

    def test_allowed_host_resolves(self) -> None:
        store = InMemoryCredentialStore()
        ref = CredentialRef("openai_key")
        store.register(
            ref,
            "sk-real-secret",
            CredentialConfig(allowed_hosts=["api.openai.com"]),
        )
        placeholder = store.get_placeholder(ref)
        value = store.resolve(placeholder, "api.openai.com")
        assert value == "sk-real-secret"

    def test_disallowed_host_returns_none(self) -> None:
        store = InMemoryCredentialStore()
        ref = CredentialRef("openai_key")
        store.register(
            ref,
            "sk-real-secret",
            CredentialConfig(allowed_hosts=["api.openai.com"]),
        )
        placeholder = store.get_placeholder(ref)
        value = store.resolve(placeholder, "evil.com")
        assert value is None

    def test_glob_pattern_matching(self) -> None:
        store = InMemoryCredentialStore()
        ref = CredentialRef("anthropic_key")
        store.register(
            ref,
            "sk-ant-secret",
            CredentialConfig(allowed_hosts=["*.anthropic.com"]),
        )
        placeholder = store.get_placeholder(ref)
        assert store.resolve(placeholder, "api.anthropic.com") == "sk-ant-secret"
        assert store.resolve(placeholder, "docs.anthropic.com") == "sk-ant-secret"
        assert store.resolve(placeholder, "evil.com") is None
