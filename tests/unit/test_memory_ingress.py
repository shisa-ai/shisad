"""Unit coverage for v0.7 memory ingress-context foundations."""

from __future__ import annotations

import pytest

from shisad.core.types import TaintLabel
from shisad.memory.ingress import DerivationPath, IngressContextRegistry, digest_content
from shisad.memory.trust import TrustGateViolation


def test_ingress_context_registry_mints_and_resolves_round_trip() -> None:
    registry = IngressContextRegistry()
    context = registry.mint(
        source_origin="user_direct",
        channel_trust="command",
        confirmation_status="user_asserted",
        taint_labels=[TaintLabel.UNTRUSTED],
        scope="user",
        source_id="turn-1",
        content="remember this",
    )

    resolved = registry.resolve(context.handle_id)
    assert resolved == context
    assert resolved.taint_labels == [TaintLabel.UNTRUSTED]
    assert resolved.content_digest == digest_content("remember this")


def test_ingress_context_registry_rejects_invalid_triple_on_mint() -> None:
    registry = IngressContextRegistry()
    with pytest.raises(TrustGateViolation):
        registry.mint(
            source_origin="user_direct",
            channel_trust="external_incoming",
            confirmation_status="user_asserted",
            scope="user",
            source_id="turn-2",
            content="forged",
        )


def test_ingress_context_direct_binding_rejects_mismatched_digest() -> None:
    registry = IngressContextRegistry()
    context = registry.mint(
        source_origin="tool_output",
        channel_trust="tool_passed",
        confirmation_status="pep_approved",
        scope="workspace",
        source_id="tool-1",
        content="tool payload",
    )

    with pytest.raises(TrustGateViolation):
        registry.validate_binding(
            context.handle_id,
            content="different payload",
            derivation_path=DerivationPath.DIRECT,
        )


def test_ingress_context_extracted_binding_requires_parent_digest_match() -> None:
    registry = IngressContextRegistry()
    context = registry.mint(
        source_origin="external_web",
        channel_trust="web_passed",
        confirmation_status="auto_accepted",
        scope="project",
        source_id="fetch-1",
        content="source material",
    )

    with pytest.raises(TrustGateViolation):
        registry.validate_binding(
            context.handle_id,
            content="derived summary",
            derivation_path=DerivationPath.SUMMARY,
            parent_digest=digest_content("wrong source"),
        )

    digest = registry.validate_binding(
        context.handle_id,
        content="derived summary",
        derivation_path=DerivationPath.SUMMARY,
        parent_digest=context.content_digest,
    )
    assert digest == digest_content("derived summary")


def test_ingress_context_unknown_handle_rejected() -> None:
    registry = IngressContextRegistry()
    with pytest.raises(TrustGateViolation):
        registry.resolve("missing-handle")
