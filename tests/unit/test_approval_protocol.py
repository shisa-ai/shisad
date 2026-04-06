"""A0 approval-protocol foundation unit coverage."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from shisad.core.approval import (
    ApprovalEnvelope,
    ConfirmationBackendRegistry,
    ConfirmationCapabilities,
    ConfirmationEvidence,
    ConfirmationFallbackPolicy,
    ConfirmationLevel,
    ConfirmationMethodLockoutTracker,
    ConfirmationRequirement,
    ConfirmationVerificationError,
    SoftwareConfirmationBackend,
    TOTPBackend,
    approval_envelope_hash,
    canonical_json_dumps,
    compute_action_digest,
    confirmation_evidence_satisfies_requirement,
    confirmation_requirement_payload,
    generate_totp_code,
    hash_recovery_code,
    merge_confirmation_requirements,
)
from shisad.core.tools.schema import ToolDefinition, ToolParameter
from shisad.core.types import Capability, ToolName
from shisad.security.credentials import (
    ApprovalFactorRecord,
    InMemoryCredentialStore,
    RecoveryCodeRecord,
)


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


def _approval_factor(
    *,
    user_id: str = "alice",
    principal_id: str = "ops-laptop",
    credential_id: str = "totp-1",
    secret_b32: str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
    recovery_code_hashes: list[str] | None = None,
) -> ApprovalFactorRecord:
    return ApprovalFactorRecord(
        credential_id=credential_id,
        user_id=user_id,
        method="totp",
        principal_id=principal_id,
        secret_b32=secret_b32,
        recovery_codes=[
            RecoveryCodeRecord(code_hash=value) for value in (recovery_code_hashes or [])
        ],
    )


def _pending_action(
    *,
    confirmation_id: str,
    user_id: str = "alice",
    credential_ids: list[str] | None = None,
    principal_ids: list[str] | None = None,
) -> SimpleNamespace:
    envelope = ApprovalEnvelope(
        approval_id=f"approval-{confirmation_id}",
        pending_action_id=confirmation_id,
        workspace_id="workspace-1",
        daemon_id="daemon-1",
        session_id="session-1",
        required_level=ConfirmationLevel.REAUTHENTICATED,
        policy_reason="manual",
        action_digest="sha256:action",
        allowed_principals=list(principal_ids or []),
        allowed_credentials=list(credential_ids or []),
        nonce="nonce",
        action_summary="test approval",
    )
    return SimpleNamespace(
        confirmation_id=confirmation_id,
        user_id=user_id,
        allowed_principals=list(principal_ids or []),
        allowed_credentials=list(credential_ids or []),
        approval_envelope=envelope,
        approval_envelope_hash=approval_envelope_hash(envelope),
        fallback_used=False,
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


def test_merge_high_tier_fallback_survives_lower_tier_confirmation_signals() -> None:
    merged = merge_confirmation_requirements(
        [
            ConfirmationRequirement(level=ConfirmationLevel.SOFTWARE),
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
    assert merged.level == ConfirmationLevel.BOUND_APPROVAL
    assert merged.fallback.mode == "allow_levels"
    assert merged.fallback.allow_levels == [ConfirmationLevel.SOFTWARE]


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


def test_confirmation_requirement_payload_preserves_routeable_round_trip() -> None:
    merged = merge_confirmation_requirements(
        [
            ConfirmationRequirement(level=ConfirmationLevel.SOFTWARE, methods=["totp"]),
            ConfirmationRequirement(level=ConfirmationLevel.SOFTWARE, methods=["webauthn"]),
        ]
    )
    assert merged is not None

    restored = ConfirmationRequirement.model_validate(confirmation_requirement_payload(merged))

    assert restored.routeable is False
    assert restored.route_reason == "confirmation_requirement_conflict:methods"


def test_confirmation_evidence_accepts_explicit_allowed_fallback_level() -> None:
    requirement = ConfirmationRequirement(
        level=ConfirmationLevel.BOUND_APPROVAL,
        fallback=ConfirmationFallbackPolicy(
            mode="allow_levels",
            allow_levels=[ConfirmationLevel.SOFTWARE],
        ),
    )
    evidence = ConfirmationEvidence(
        level=ConfirmationLevel.SOFTWARE,
        method="software",
        backend_id="software.default",
        approval_envelope_hash="sha256:test-envelope",
        action_digest="sha256:test-action",
        decision_nonce="nonce-1",
        fallback_used=True,
    )

    assert (
        confirmation_evidence_satisfies_requirement(
            requirement=requirement,
            evidence=evidence,
            backend=SoftwareConfirmationBackend(),
        )
        is True
    )


def test_confirmation_evidence_rejects_allowed_fallback_level_without_fallback_marker() -> None:
    requirement = ConfirmationRequirement(
        level=ConfirmationLevel.BOUND_APPROVAL,
        fallback=ConfirmationFallbackPolicy(
            mode="allow_levels",
            allow_levels=[ConfirmationLevel.SOFTWARE],
        ),
    )
    evidence = ConfirmationEvidence(
        level=ConfirmationLevel.SOFTWARE,
        method="software",
        backend_id="software.default",
        approval_envelope_hash="sha256:test-envelope",
        action_digest="sha256:test-action",
        decision_nonce="nonce-1",
        fallback_used=False,
    )

    assert (
        confirmation_evidence_satisfies_requirement(
            requirement=requirement,
            evidence=evidence,
            backend=SoftwareConfirmationBackend(),
        )
        is False
    )


def test_generate_totp_code_matches_rfc6238_sha1_vector() -> None:
    secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    assert (
        generate_totp_code(
            secret,
            now=datetime(1970, 1, 1, 0, 0, 59, tzinfo=UTC),
            digits=8,
        )
        == "94287082"
    )
    assert (
        generate_totp_code(
            secret,
            now=datetime(1970, 1, 1, 0, 1, 29, tzinfo=UTC),
            digits=8,
        )
        == "37359152"
    )
    assert (
        generate_totp_code(
            secret,
            now=datetime(1970, 1, 1, 0, 1, 30, tzinfo=UTC),
            digits=8,
        )
        == "26969429"
    )


def test_registry_only_routes_totp_for_users_with_enrolled_factor(tmp_path) -> None:
    store = InMemoryCredentialStore()
    store.set_approval_store_path(tmp_path / "credentials.json")
    backend = TOTPBackend(credential_store=store)
    registry = ConfirmationBackendRegistry()
    registry.register(backend)

    requirement = ConfirmationRequirement(
        level=ConfirmationLevel.REAUTHENTICATED,
        methods=["totp"],
    )
    assert registry.resolve(requirement, user_id="alice") is None

    store.register_approval_factor(_approval_factor(user_id="alice"))

    resolved = registry.resolve(requirement, user_id="alice")
    assert resolved is not None
    assert resolved.backend.method == "totp"
    assert resolved.fallback_used is False


def test_totp_backend_rejects_same_window_reuse_across_pending_actions(tmp_path) -> None:
    store = InMemoryCredentialStore()
    store.set_approval_store_path(tmp_path / "credentials.json")
    factor = _approval_factor()
    store.register_approval_factor(factor)
    backend = TOTPBackend(credential_store=store)
    now = datetime(2026, 4, 6, 12, 0, 0, tzinfo=UTC)
    code = generate_totp_code(factor.secret_b32, now=now)

    evidence = backend.verify(
        pending_action=_pending_action(confirmation_id="c-1"),
        params={
            "decision_nonce": "nonce-1",
            "approval_method": "totp",
            "proof": {"totp_code": code},
        },
        now=now,
    )

    assert evidence.level == ConfirmationLevel.REAUTHENTICATED
    assert evidence.method == "totp"
    assert evidence.approver_principal_id == factor.principal_id
    assert evidence.credential_id == factor.credential_id

    with pytest.raises(ConfirmationVerificationError, match="totp_code_reused"):
        backend.verify(
            pending_action=_pending_action(confirmation_id="c-2"),
            params={
                "decision_nonce": "nonce-2",
                "approval_method": "totp",
                "proof": {"totp_code": code},
            },
            now=now + timedelta(seconds=5),
        )


def test_totp_backend_consumes_recovery_codes_once(tmp_path) -> None:
    store = InMemoryCredentialStore()
    store.set_approval_store_path(tmp_path / "credentials.json")
    recovery_code = "ABCD-EFGH"
    factor = _approval_factor(
        recovery_code_hashes=[hash_recovery_code(recovery_code)]
    )
    store.register_approval_factor(factor)
    backend = TOTPBackend(credential_store=store)
    now = datetime(2026, 4, 6, 12, 0, 0, tzinfo=UTC)

    evidence = backend.verify(
        pending_action=_pending_action(confirmation_id="c-1"),
        params={
            "decision_nonce": "nonce-1",
            "approval_method": "recovery_code",
            "proof": {"recovery_code": recovery_code},
        },
        now=now,
    )

    assert evidence.level == ConfirmationLevel.REAUTHENTICATED
    assert evidence.method == "recovery_code"
    assert evidence.credential_id == factor.credential_id

    with pytest.raises(ConfirmationVerificationError, match="recovery_code_reused"):
        backend.verify(
            pending_action=_pending_action(confirmation_id="c-2"),
            params={
                "decision_nonce": "nonce-2",
                "approval_method": "recovery_code",
                "proof": {"recovery_code": recovery_code},
            },
            now=now,
        )


def test_canonical_json_rejects_naive_datetime() -> None:
    with pytest.raises(ValueError, match="naive datetimes"):
        canonical_json_dumps({"created_at": datetime(2026, 4, 6, 12, 0, 0)})


def test_lockout_tracker_quarantines_malformed_state_file(tmp_path) -> None:
    state_path = tmp_path / "confirmation_lockouts.json"
    state_path.write_text("{not-json", encoding="utf-8")

    tracker = ConfirmationMethodLockoutTracker(state_path=state_path)

    assert tracker.status(user_id="alice", method="totp") is None
    assert not state_path.exists()
    quarantined = list(tmp_path.glob("confirmation_lockouts.json.corrupt.*"))
    assert len(quarantined) == 1
