"""A0 approval-protocol foundation unit coverage."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

from shisad.core.approval import (
    ApprovalEnvelope,
    ConfirmationBackendRegistry,
    ConfirmationCapabilities,
    ConfirmationFallbackPolicy,
    ConfirmationLevel,
    ConfirmationRequirement,
    ConfirmationVerificationError,
    SoftwareConfirmationBackend,
    approval_envelope_hash,
    canonical_json_dumps,
    compute_action_digest,
    merge_confirmation_requirements,
)
from shisad.core.tools.schema import ToolDefinition, ToolParameter
from shisad.core.types import Capability, ToolName


def _deploy_tool() -> ToolDefinition:
    return ToolDefinition(
        name=ToolName("deploy.production"),
        description="Deploy a validated release branch to production.",
        parameters=[
            ToolParameter(name="branch", type="string", required=True),
            ToolParameter(name="environment", type="string", required=True),
        ],
        capabilities_required=[Capability.HTTP_REQUEST],
    )


def test_action_digest_matches_reference_vector() -> None:
    tool = _deploy_tool()
    digest = compute_action_digest(
        tool_definition=tool,
        arguments={
            "branch": "release/2026-04-05",
            "environment": "prod",
        },
        destinations=["prod-deploy.example.com"],
    )
    canonical = (
        "{"
        "\"arguments\":{\"branch\":\"release/2026-04-05\",\"environment\":\"prod\"},"
        "\"destinations\":[\"prod-deploy.example.com\"],"
        "\"schema_version\":\"shisad.action_digest.v1\","
        "\"tool_name\":\"deploy.production\","
        f"\"tool_schema_hash\":\"sha256:{tool.schema_hash()}\""
        "}"
    )
    expected = f"sha256:{hashlib.sha256(canonical.encode('utf-8')).hexdigest()}"
    assert digest == expected


def test_approval_envelope_hash_ignores_action_summary() -> None:
    envelope = ApprovalEnvelope(
        approval_id="approval-1",
        pending_action_id="pending-1",
        workspace_id="workspace-1",
        daemon_id="daemon-1",
        session_id="session-1",
        required_level=ConfirmationLevel.SOFTWARE,
        policy_reason="deploy.production requires explicit approval",
        action_digest="sha256:abc123",
        allowed_principals=["workspace_owner"],
        allowed_credentials=[],
        expires_at=datetime(2026, 4, 5, 18, 40, tzinfo=UTC),
        nonce="b64:nonce",
        intent_envelope_hash=None,
        action_summary="Deploy release/2026-04-05 to prod",
    )
    variant = envelope.model_copy(update={"action_summary": "A different preview text"})

    canonical = (
        "{"
        "\"action_digest\":\"sha256:abc123\","
        "\"allowed_credentials\":[],"
        "\"allowed_principals\":[\"workspace_owner\"],"
        "\"approval_id\":\"approval-1\","
        "\"daemon_id\":\"daemon-1\","
        "\"expires_at\":\"2026-04-05T18:40:00Z\","
        "\"intent_envelope_hash\":null,"
        "\"nonce\":\"b64:nonce\","
        "\"pending_action_id\":\"pending-1\","
        "\"policy_reason\":\"deploy.production requires explicit approval\","
        "\"required_level\":\"software\","
        "\"schema_version\":\"shisad.approval.v1\","
        "\"session_id\":\"session-1\","
        "\"workspace_id\":\"workspace-1\""
        "}"
    )
    expected = f"sha256:{hashlib.sha256(canonical.encode('utf-8')).hexdigest()}"

    assert approval_envelope_hash(envelope) == expected
    assert approval_envelope_hash(variant) == expected


def test_registry_requires_explicit_fallback_for_lower_level_resolution() -> None:
    registry = ConfirmationBackendRegistry()
    registry.register(SoftwareConfirmationBackend())

    strict = registry.resolve(
        ConfirmationRequirement(level=ConfirmationLevel.BOUND_APPROVAL)
    )
    assert strict is None

    fallback = registry.resolve(
        ConfirmationRequirement(
            level=ConfirmationLevel.BOUND_APPROVAL,
            fallback=ConfirmationFallbackPolicy(
                mode="allow_levels",
                allow_levels=[ConfirmationLevel.SOFTWARE],
            ),
        )
    )
    assert fallback is not None
    assert fallback.backend.method == "software"
    assert fallback.fallback_used is True


def test_registry_filters_backends_by_required_capabilities() -> None:
    registry = ConfirmationBackendRegistry()
    registry.register(SoftwareConfirmationBackend())

    resolved = registry.resolve(
        ConfirmationRequirement(
            level=ConfirmationLevel.SOFTWARE,
            require_capabilities=ConfirmationCapabilities(
                trusted_display=True,
            ),
        )
    )
    assert resolved is None


def test_merge_preserves_lower_level_constraints_when_risk_escalation_wins() -> None:
    merged = merge_confirmation_requirements(
        [
            ConfirmationRequirement(
                level=ConfirmationLevel.SOFTWARE,
                methods=["webauthn"],
                allowed_principals=["alice"],
            ),
            ConfirmationRequirement(level=ConfirmationLevel.BOUND_APPROVAL),
        ]
    )
    assert merged is not None
    assert merged.level == ConfirmationLevel.BOUND_APPROVAL
    assert merged.methods == ["webauthn"]
    assert merged.allowed_principals == ["alice"]
    assert merged.routeable is True


def test_merge_conflicting_method_constraints_fail_closed() -> None:
    merged = merge_confirmation_requirements(
        [
            ConfirmationRequirement(level=ConfirmationLevel.SOFTWARE, methods=["totp"]),
            ConfirmationRequirement(level=ConfirmationLevel.SOFTWARE, methods=["webauthn"]),
        ]
    )
    assert merged is not None
    assert merged.methods == []
    assert merged.routeable is False
    assert merged.route_reason == "confirmation_requirement_conflict:methods"

    registry = ConfirmationBackendRegistry()
    registry.register(SoftwareConfirmationBackend())
    assert registry.resolve(merged) is None


def test_merge_fallback_requires_consensus_for_downgrade() -> None:
    merged = merge_confirmation_requirements(
        [
            ConfirmationRequirement(level=ConfirmationLevel.BOUND_APPROVAL),
            ConfirmationRequirement(
                level=ConfirmationLevel.BOUND_APPROVAL,
                fallback=ConfirmationFallbackPolicy(
                    mode="allow_levels",
                    allow_levels=[ConfirmationLevel.SOFTWARE],
                ),
            ),
        ]
    )
    assert merged is not None
    assert merged.fallback.mode == "deny"
    assert merged.fallback.allow_levels == []


def test_registry_rejects_principal_restricted_software_backend() -> None:
    registry = ConfirmationBackendRegistry()
    registry.register(SoftwareConfirmationBackend())

    resolved = registry.resolve(
        ConfirmationRequirement(
            level=ConfirmationLevel.SOFTWARE,
            allowed_principals=["workspace_owner"],
        )
    )
    assert resolved is None


def test_software_backend_requires_approval_envelope_hash() -> None:
    backend = SoftwareConfirmationBackend()
    pending = SimpleNamespace(
        confirmation_id="c-1",
        approval_envelope_hash="",
        approval_envelope=None,
        allowed_principals=[],
        allowed_credentials=[],
        fallback_used=False,
    )

    with pytest.raises(ConfirmationVerificationError, match="approval_envelope_missing"):
        backend.verify(pending_action=pending, params={"decision_nonce": "nonce-1"})


def test_canonical_json_rejects_naive_datetime() -> None:
    with pytest.raises(ValueError, match="naive datetimes"):
        canonical_json_dumps({"created_at": datetime(2026, 4, 6, 12, 0, 0)})
