"""A0 approval-protocol foundation unit coverage."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

import shisad.core.approval as approval_module
from shisad.core.approval import (
    ApprovalEnvelope,
    BindingScope,
    ConfirmationBackendRegistry,
    ConfirmationCapabilities,
    ConfirmationEvidence,
    ConfirmationFallbackPolicy,
    ConfirmationLevel,
    ConfirmationMethodLockoutTracker,
    ConfirmationRequirement,
    ConfirmationVerificationError,
    IntentAction,
    IntentEnvelope,
    IntentPolicyContext,
    LocalFido2Backend,
    ReviewSurface,
    SoftwareConfirmationBackend,
    TOTPBackend,
    WebAuthnBackend,
    _eip712_digest,
    _eip712_hash_struct,
    _origin_matches,
    approval_envelope_hash,
    canonical_json_dumps,
    compute_action_digest,
    confirmation_evidence_satisfies_requirement,
    confirmation_requirement_payload,
    generate_totp_code,
    hash_recovery_code,
    intent_envelope_hash,
    merge_confirmation_requirements,
)
from shisad.core.tools.schema import ToolDefinition, ToolParameter
from shisad.core.types import Capability, ToolName
from shisad.daemon.handlers._impl import PendingAction
from shisad.security.credentials import (
    ApprovalFactorRecord,
    InMemoryCredentialStore,
    RecoveryCodeRecord,
)
from tests.helpers.approval import make_pending_action
from tests.helpers.webauthn import make_authentication_payload, make_registration_payload


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
) -> PendingAction:
    # ADV-L4: return a real ``PendingAction`` instead of ``SimpleNamespace``
    # so added-required-fields on the dataclass immediately fail these tests
    # rather than slipping through getattr-with-default backend access.
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
    return make_pending_action(
        confirmation_id=confirmation_id,
        user_id=user_id,
        allowed_principals=principal_ids,
        allowed_credentials=credential_ids,
        approval_envelope=envelope,
        approval_envelope_hash=approval_envelope_hash(envelope),
        required_level=ConfirmationLevel.REAUTHENTICATED,
        selected_backend_id="software.default",
        selected_backend_method="software",
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
        '"arguments":{"branch":"release/2026-04-05","environment":"prod"},'
        '"destinations":["prod-deploy.example.com"],'
        '"schema_version":"shisad.action_digest.v1",'
        '"tool_name":"deploy.production",'
        f'"tool_schema_hash":"sha256:{tool.schema_hash()}"'
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
        '"action_digest":"sha256:abc123",'
        '"allowed_credentials":[],'
        '"allowed_principals":["workspace_owner"],'
        '"approval_id":"approval-1",'
        '"daemon_id":"daemon-1",'
        '"expires_at":"2026-04-05T18:40:00Z",'
        '"intent_envelope_hash":null,'
        '"nonce":"b64:nonce",'
        '"pending_action_id":"pending-1",'
        '"policy_reason":"deploy.production requires explicit approval",'
        '"required_level":"software",'
        '"schema_version":"shisad.approval.v1",'
        '"session_id":"session-1",'
        '"workspace_id":"workspace-1"'
        "}"
    )
    expected = f"sha256:{hashlib.sha256(canonical.encode('utf-8')).hexdigest()}"

    assert approval_envelope_hash(envelope) == expected
    assert approval_envelope_hash(variant) == expected


def test_intent_envelope_hash_matches_reference_vector() -> None:
    envelope = IntentEnvelope(
        intent_id="intent-1",
        agent_id="daemon-1",
        workspace_id="workspace-1",
        session_id="session-1",
        created_at=datetime(2026, 4, 8, 12, 0, tzinfo=UTC),
        expires_at=datetime(2026, 4, 8, 12, 5, tzinfo=UTC),
        action=IntentAction(
            tool="deploy.production",
            display_summary="Deploy release/2026-04-08 to prod",
            parameters={
                "branch": "release/2026-04-08",
                "environment": "prod",
            },
            destinations=["prod-deploy.example.com"],
        ),
        policy_context=IntentPolicyContext(
            required_level=ConfirmationLevel.SIGNED_AUTHORIZATION,
            confirmation_reason="deploy.production requires signer approval",
            matched_rule="deploy.production",
            action_digest="sha256:abc123",
        ),
        nonce="b64:nonce",
    )
    canonical = (
        "{"
        '"action":{"destinations":["prod-deploy.example.com"],'
        '"display_summary":"Deploy release/2026-04-08 to prod",'
        '"parameters":{"branch":"release/2026-04-08","environment":"prod"},'
        '"tool":"deploy.production"},'
        '"agent_id":"daemon-1",'
        '"created_at":"2026-04-08T12:00:00Z",'
        '"expires_at":"2026-04-08T12:05:00Z",'
        '"intent_id":"intent-1",'
        '"nonce":"b64:nonce",'
        '"policy_context":{"action_digest":"sha256:abc123",'
        '"confirmation_reason":"deploy.production requires signer approval",'
        '"matched_rule":"deploy.production",'
        '"required_level":"signed_authorization"},'
        '"schema_version":"shisad.intent.v1",'
        '"session_id":"session-1",'
        '"workspace_id":"workspace-1"'
        "}"
    )
    expected = f"sha256:{hashlib.sha256(canonical.encode('utf-8')).hexdigest()}"

    assert intent_envelope_hash(envelope) == expected


def _ledger_reference_intent() -> IntentEnvelope:
    return IntentEnvelope(
        intent_id="intent-ledger-1",
        agent_id="daemon-1",
        workspace_id="workspace-1",
        session_id="session-1",
        created_at=datetime(2026, 4, 10, 12, 0, tzinfo=UTC),
        expires_at=datetime(2026, 4, 10, 12, 5, tzinfo=UTC),
        action=IntentAction(
            tool="deploy.production",
            display_summary="Deploy v2.1.0 to production cluster",
            parameters={"version": "2.1.0", "target": "prod"},
            destinations=["deploy.example.com"],
        ),
        policy_context=IntentPolicyContext(
            required_level=ConfirmationLevel.TRUSTED_DISPLAY_AUTHORIZATION,
            confirmation_reason="deploy.production requires trusted-display",
            matched_rule="deploy.production",
            action_digest="sha256:action-ledger",
        ),
        nonce="b64:intent-nonce-ledger",
    )


def test_eip712_digest_matches_full_intent_hash_reference_vector() -> None:
    envelope = _ledger_reference_intent()

    assert intent_envelope_hash(envelope) == (
        "sha256:94f0e3e648c007a6069c42ca5df7f2386a9621b5264aac70f4228ea51a4276b7"
    )
    assert _eip712_digest(envelope).hex() == (
        "19a9ec7e7b1d4a348cd3ba247c6f7b499d73049649e245d0a0c7bb59fbcbb5ed"
    )


def test_eip712_digest_changes_when_full_intent_only_field_changes() -> None:
    envelope = _ledger_reference_intent()
    changed = envelope.model_copy(update={"workspace_id": "workspace-2"})

    assert _eip712_digest(changed) != _eip712_digest(envelope)


def test_eip712_uint256_rejects_non_scalar_value() -> None:
    with pytest.raises(ValueError, match="chainId"):
        _eip712_hash_struct(
            "EIP712Domain",
            {"name": "shisad", "version": "1", "chainId": object()},
        )


def test_eip712_hash_struct_rejects_unsupported_field_type(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(
        approval_module._EIP712_TYPES,
        "UnsupportedStruct",
        [("payload", "bytes32")],
    )

    with pytest.raises(ValueError, match=r"UnsupportedStruct\.payload"):
        _eip712_hash_struct("UnsupportedStruct", {"payload": "0x" + "00" * 32})


def test_provider_ui_signature_satisfies_l3_but_not_l4() -> None:
    backend = SimpleNamespace(
        capabilities=ConfirmationCapabilities(
            principal_binding=True,
            full_intent_signature=True,
            third_party_verifiable=True,
            trusted_display=True,
        )
    )
    evidence = ConfirmationEvidence(
        level=ConfirmationLevel.SIGNED_AUTHORIZATION,
        method="kms",
        approver_principal_id="finance-owner",
        credential_id="kms:finance-primary",
        binding_scope=BindingScope.FULL_INTENT,
        review_surface=ReviewSurface.PROVIDER_UI,
        third_party_verifiable=True,
        approval_envelope_hash="sha256:approval",
        action_digest="sha256:action",
        decision_nonce="nonce",
        intent_envelope_hash="sha256:intent",
        signature="base64:signature",
        signer_key_id="kms:finance-primary",
    )

    assert confirmation_evidence_satisfies_requirement(
        requirement=ConfirmationRequirement(
            level=ConfirmationLevel.SIGNED_AUTHORIZATION,
            methods=["kms"],
            allowed_principals=["finance-owner"],
            allowed_credentials=["kms:finance-primary"],
            require_capabilities=ConfirmationCapabilities(
                principal_binding=True,
                full_intent_signature=True,
                third_party_verifiable=True,
            ),
        ),
        evidence=evidence,
        backend=backend,
    )
    assert not confirmation_evidence_satisfies_requirement(
        requirement=ConfirmationRequirement(
            level=ConfirmationLevel.TRUSTED_DISPLAY_AUTHORIZATION,
            methods=["kms"],
            allowed_principals=["finance-owner"],
            allowed_credentials=["kms:finance-primary"],
            require_capabilities=ConfirmationCapabilities(
                principal_binding=True,
                full_intent_signature=True,
                third_party_verifiable=True,
                trusted_display=True,
            ),
        ),
        evidence=evidence,
        backend=backend,
    )


def test_blind_sign_evidence_cannot_satisfy_l3_policy() -> None:
    backend = SimpleNamespace(
        capabilities=ConfirmationCapabilities(
            principal_binding=True,
            full_intent_signature=True,
            third_party_verifiable=True,
            trusted_display=True,
            blind_sign_detection=True,
        )
    )
    evidence = ConfirmationEvidence(
        level=ConfirmationLevel.BOUND_APPROVAL,
        method="ledger_clear_sign",
        approver_principal_id="finance-owner",
        credential_id="ledger:alice-stax",
        binding_scope=BindingScope.FULL_INTENT,
        review_surface=ReviewSurface.OPAQUE_DEVICE,
        third_party_verifiable=True,
        approval_envelope_hash="sha256:approval",
        action_digest="sha256:action",
        decision_nonce="nonce",
        intent_envelope_hash="sha256:intent",
        signature="base64:signature",
        signer_key_id="ledger:alice-stax",
        blind_sign_detected=True,
    )

    assert not confirmation_evidence_satisfies_requirement(
        requirement=ConfirmationRequirement(
            level=ConfirmationLevel.SIGNED_AUTHORIZATION,
            methods=["ledger_clear_sign"],
            allowed_principals=["finance-owner"],
            allowed_credentials=["ledger:alice-stax"],
            require_capabilities=ConfirmationCapabilities(
                principal_binding=True,
                full_intent_signature=True,
                third_party_verifiable=True,
            ),
        ),
        evidence=evidence,
        backend=backend,
    )


def test_registry_requires_explicit_fallback_for_lower_level_resolution() -> None:
    registry = ConfirmationBackendRegistry()
    registry.register(SoftwareConfirmationBackend())

    strict = registry.resolve(ConfirmationRequirement(level=ConfirmationLevel.BOUND_APPROVAL))
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
    # ADV-L4: real ``PendingAction`` rather than ``SimpleNamespace`` so the
    # missing-envelope error path remains sensitive to dataclass drift.
    backend = SoftwareConfirmationBackend()
    pending = make_pending_action(
        confirmation_id="c-1",
        approval_envelope=None,
        approval_envelope_hash="",
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
    factor = _approval_factor(recovery_code_hashes=[hash_recovery_code(recovery_code)])
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


def test_webauthn_backend_registers_and_verifies_bound_approval(tmp_path) -> None:
    store = InMemoryCredentialStore()
    store.set_approval_store_path(tmp_path / "credentials.json")
    backend = WebAuthnBackend(
        credential_store=store,
        approval_origin="https://approve.example.com",
        rp_id="approve.example.com",
    )

    public_key_options, state = backend.registration_begin(
        user_id="alice",
        principal_id="ops-phone",
        credential_id="webauthn-1",
    )
    credential, registration_payload = make_registration_payload(
        public_key_options=public_key_options,
        origin="https://approve.example.com",
        rp_id="approve.example.com",
    )
    factor = backend.registration_complete(
        credential_id="webauthn-1",
        user_id="alice",
        principal_id="ops-phone",
        created_at=datetime(2026, 4, 6, 12, 0, tzinfo=UTC),
        state=state,
        response_payload=registration_payload,
    )
    store.register_approval_factor(factor)

    pending = _pending_action(
        confirmation_id="c-1",
        credential_ids=[factor.credential_id],
        principal_ids=[factor.principal_id],
    )
    request_options = backend.approval_request_options(pending_action=pending)
    assertion = make_authentication_payload(
        public_key_options=request_options,
        credential=credential,
    )

    evidence = backend.verify(
        pending_action=pending,
        params={
            "decision_nonce": "nonce-1",
            "approval_method": "webauthn",
            "proof": assertion,
        },
        now=datetime(2026, 4, 6, 12, 1, tzinfo=UTC),
    )

    assert evidence.level == ConfirmationLevel.BOUND_APPROVAL
    assert evidence.method == "webauthn"
    assert evidence.credential_id == factor.credential_id
    assert evidence.approver_principal_id == factor.principal_id
    assert evidence.approval_envelope_hash == pending.approval_envelope_hash
    stored = store.list_approval_factors(user_id="alice", method="webauthn")
    assert len(stored) == 1
    assert stored[0].webauthn_sign_count == credential.sign_count


def test_local_fido2_backend_registers_and_verifies_bound_approval(tmp_path) -> None:
    store = InMemoryCredentialStore()
    store.set_approval_store_path(tmp_path / "credentials.json")
    backend = LocalFido2Backend(
        credential_store=store,
        daemon_id="deadbeefcafebabe",
    )

    public_key_options, state = backend.registration_begin(
        user_id="alice",
        principal_id="ops-key",
        credential_id="local_fido2-1",
    )
    credential, registration_payload = make_registration_payload(
        public_key_options=public_key_options,
        origin=backend.approval_origin,
        rp_id=backend.rp_id,
    )
    factor = backend.registration_complete(
        credential_id="local_fido2-1",
        user_id="alice",
        principal_id="ops-key",
        created_at=datetime(2026, 4, 7, 9, 0, tzinfo=UTC),
        state=state,
        response_payload=registration_payload,
    )
    store.register_approval_factor(factor)

    pending = _pending_action(
        confirmation_id="c-local",
        credential_ids=[factor.credential_id],
        principal_ids=[factor.principal_id],
    )
    request_options = backend.approval_request_options(pending_action=pending)
    assertion = make_authentication_payload(
        public_key_options=request_options,
        credential=credential,
    )

    evidence = backend.verify(
        pending_action=pending,
        params={
            "decision_nonce": "nonce-local",
            "approval_method": "local_fido2",
            "proof": assertion,
        },
        now=datetime(2026, 4, 7, 9, 1, tzinfo=UTC),
    )

    assert evidence.level == ConfirmationLevel.BOUND_APPROVAL
    assert evidence.method == "local_fido2"
    assert evidence.credential_id == factor.credential_id
    assert evidence.approver_principal_id == factor.principal_id
    assert evidence.review_surface.value == "host_rendered"
    stored = store.list_approval_factors(user_id="alice", method="local_fido2")
    assert len(stored) == 1
    assert stored[0].method == "local_fido2"
    assert stored[0].webauthn_sign_count == credential.sign_count


def test_webauthn_backend_rejects_duplicate_credential_registration(tmp_path) -> None:
    store = InMemoryCredentialStore()
    store.set_approval_store_path(tmp_path / "credentials.json")
    backend = WebAuthnBackend(
        credential_store=store,
        approval_origin="https://approve.example.com",
        rp_id="approve.example.com",
    )

    public_key_options, state = backend.registration_begin(
        user_id="alice",
        principal_id="ops-phone",
        credential_id="webauthn-1",
    )
    _credential, registration_payload = make_registration_payload(
        public_key_options=public_key_options,
        origin="https://approve.example.com",
        rp_id="approve.example.com",
    )
    factor = backend.registration_complete(
        credential_id="webauthn-1",
        user_id="alice",
        principal_id="ops-phone",
        created_at=datetime(2026, 4, 6, 12, 0, tzinfo=UTC),
        state=state,
        response_payload=registration_payload,
    )
    store.register_approval_factor(factor)

    with pytest.raises(
        ConfirmationVerificationError,
        match="webauthn_credential_already_registered",
    ):
        backend.registration_complete(
            credential_id="webauthn-2",
            user_id="alice",
            principal_id="ops-phone-2",
            created_at=datetime(2026, 4, 6, 12, 1, tzinfo=UTC),
            state=state,
            response_payload=registration_payload,
        )


def test_webauthn_backend_accepts_default_port_origin_without_explicit_port_in_browser(
    tmp_path,
) -> None:
    store = InMemoryCredentialStore()
    store.set_approval_store_path(tmp_path / "credentials.json")
    backend = WebAuthnBackend(
        credential_store=store,
        approval_origin="https://approve.example.com:443",
        rp_id="approve.example.com",
    )

    public_key_options, state = backend.registration_begin(
        user_id="alice",
        principal_id="ops-phone",
        credential_id="webauthn-1",
    )
    credential, registration_payload = make_registration_payload(
        public_key_options=public_key_options,
        origin="https://approve.example.com",
        rp_id="approve.example.com",
    )
    factor = backend.registration_complete(
        credential_id="webauthn-1",
        user_id="alice",
        principal_id="ops-phone",
        created_at=datetime(2026, 4, 6, 12, 0, tzinfo=UTC),
        state=state,
        response_payload=registration_payload,
    )
    store.register_approval_factor(factor)

    pending = _pending_action(
        confirmation_id="c-1",
        credential_ids=[factor.credential_id],
        principal_ids=[factor.principal_id],
    )
    request_options = backend.approval_request_options(pending_action=pending)
    assertion = make_authentication_payload(
        public_key_options=request_options,
        credential=credential,
    )

    evidence = backend.verify(
        pending_action=pending,
        params={
            "decision_nonce": "nonce-1",
            "approval_method": "webauthn",
            "proof": assertion,
        },
        now=datetime(2026, 4, 6, 12, 1, tzinfo=UTC),
    )

    assert backend.approval_origin == "https://approve.example.com"
    assert request_options["userVerification"] == "required"
    assert evidence.method == "webauthn"


@pytest.mark.parametrize(
    ("candidate_origin", "expected_origin"),
    [
        ("https://approve.example.com:443", "https://approve.example.com"),
        ("https://approve.example.com/", "https://approve.example.com"),
        ("http://127.0.0.1:80", "http://127.0.0.1"),
        ("http://127.0.0.1/", "http://127.0.0.1"),
    ],
)
def test_webauthn_origin_matcher_accepts_equivalent_root_origin_forms(
    candidate_origin: str,
    expected_origin: str,
) -> None:
    assert _origin_matches(candidate_origin, expected_origin) is True


@pytest.mark.parametrize(
    "invalid_origin",
    [
        "https://approve.example.com/evil-path",
        "https://approve.example.com?evil=1",
        "https://approve.example.com#evil",
        "https://user@approve.example.com",
    ],
)
def test_webauthn_origin_matcher_rejects_non_origin_forms(invalid_origin: str) -> None:
    assert _origin_matches(invalid_origin, "https://approve.example.com") is False


@pytest.mark.parametrize(
    "browser_origin",
    [
        "https://approve.example.com:443",
        "https://approve.example.com/",
    ],
)
def test_webauthn_backend_accepts_equivalent_client_origins_during_registration(
    tmp_path,
    browser_origin: str,
) -> None:
    store = InMemoryCredentialStore()
    store.set_approval_store_path(tmp_path / "credentials.json")
    backend = WebAuthnBackend(
        credential_store=store,
        approval_origin="https://approve.example.com",
        rp_id="approve.example.com",
    )

    public_key_options, state = backend.registration_begin(
        user_id="alice",
        principal_id="ops-phone",
        credential_id="webauthn-1",
    )
    _credential, registration_payload = make_registration_payload(
        public_key_options=public_key_options,
        origin=browser_origin,
        rp_id="approve.example.com",
    )

    factor = backend.registration_complete(
        credential_id="webauthn-1",
        user_id="alice",
        principal_id="ops-phone",
        created_at=datetime(2026, 4, 6, 12, 0, tzinfo=UTC),
        state=state,
        response_payload=registration_payload,
    )

    assert factor.method == "webauthn"
    assert factor.principal_id == "ops-phone"


@pytest.mark.parametrize(
    "browser_origin",
    [
        "https://approve.example.com:443",
        "https://approve.example.com/",
    ],
)
def test_webauthn_backend_accepts_equivalent_client_origins_during_assertion(
    tmp_path,
    browser_origin: str,
) -> None:
    store = InMemoryCredentialStore()
    store.set_approval_store_path(tmp_path / "credentials.json")
    backend = WebAuthnBackend(
        credential_store=store,
        approval_origin="https://approve.example.com",
        rp_id="approve.example.com",
    )

    public_key_options, state = backend.registration_begin(
        user_id="alice",
        principal_id="ops-phone",
        credential_id="webauthn-1",
    )
    credential, registration_payload = make_registration_payload(
        public_key_options=public_key_options,
        origin="https://approve.example.com",
        rp_id="approve.example.com",
    )
    factor = backend.registration_complete(
        credential_id="webauthn-1",
        user_id="alice",
        principal_id="ops-phone",
        created_at=datetime(2026, 4, 6, 12, 0, tzinfo=UTC),
        state=state,
        response_payload=registration_payload,
    )
    store.register_approval_factor(factor)

    pending = _pending_action(
        confirmation_id="c-1",
        credential_ids=[factor.credential_id],
        principal_ids=[factor.principal_id],
    )
    request_options = backend.approval_request_options(pending_action=pending)
    credential.origin = browser_origin
    assertion = make_authentication_payload(
        public_key_options=request_options,
        credential=credential,
    )

    evidence = backend.verify(
        pending_action=pending,
        params={
            "decision_nonce": "nonce-1",
            "approval_method": "webauthn",
            "proof": assertion,
        },
        now=datetime(2026, 4, 6, 12, 1, tzinfo=UTC),
    )

    assert evidence.method == "webauthn"
    assert evidence.approval_envelope_hash == pending.approval_envelope_hash


@pytest.mark.parametrize(
    "invalid_origin",
    [
        "https://approve.example.com/evil-path",
        "https://approve.example.com?evil=1",
        "https://approve.example.com#evil",
    ],
)
def test_webauthn_backend_rejects_non_origin_client_data_during_registration(
    tmp_path,
    invalid_origin: str,
) -> None:
    store = InMemoryCredentialStore()
    store.set_approval_store_path(tmp_path / "credentials.json")
    backend = WebAuthnBackend(
        credential_store=store,
        approval_origin="https://approve.example.com",
        rp_id="approve.example.com",
    )

    public_key_options, state = backend.registration_begin(
        user_id="alice",
        principal_id="ops-phone",
        credential_id="webauthn-1",
    )
    _credential, registration_payload = make_registration_payload(
        public_key_options=public_key_options,
        origin=invalid_origin,
        rp_id="approve.example.com",
    )

    with pytest.raises(ConfirmationVerificationError, match="invalid_webauthn_registration"):
        backend.registration_complete(
            credential_id="webauthn-1",
            user_id="alice",
            principal_id="ops-phone",
            created_at=datetime(2026, 4, 6, 12, 0, tzinfo=UTC),
            state=state,
            response_payload=registration_payload,
        )


@pytest.mark.parametrize(
    "invalid_origin",
    [
        "https://approve.example.com/evil-path",
        "https://approve.example.com?evil=1",
        "https://approve.example.com#evil",
    ],
)
def test_webauthn_backend_rejects_non_origin_client_data_during_assertion(
    tmp_path,
    invalid_origin: str,
) -> None:
    store = InMemoryCredentialStore()
    store.set_approval_store_path(tmp_path / "credentials.json")
    backend = WebAuthnBackend(
        credential_store=store,
        approval_origin="https://approve.example.com",
        rp_id="approve.example.com",
    )

    public_key_options, state = backend.registration_begin(
        user_id="alice",
        principal_id="ops-phone",
        credential_id="webauthn-1",
    )
    credential, registration_payload = make_registration_payload(
        public_key_options=public_key_options,
        origin="https://approve.example.com",
        rp_id="approve.example.com",
    )
    factor = backend.registration_complete(
        credential_id="webauthn-1",
        user_id="alice",
        principal_id="ops-phone",
        created_at=datetime(2026, 4, 6, 12, 0, tzinfo=UTC),
        state=state,
        response_payload=registration_payload,
    )
    store.register_approval_factor(factor)

    pending = _pending_action(
        confirmation_id="c-1",
        credential_ids=[factor.credential_id],
        principal_ids=[factor.principal_id],
    )
    request_options = backend.approval_request_options(pending_action=pending)
    credential.origin = invalid_origin
    assertion = make_authentication_payload(
        public_key_options=request_options,
        credential=credential,
    )

    with pytest.raises(ConfirmationVerificationError, match="invalid_webauthn_assertion"):
        backend.verify(
            pending_action=pending,
            params={
                "decision_nonce": "nonce-1",
                "approval_method": "webauthn",
                "proof": assertion,
            },
            now=datetime(2026, 4, 6, 12, 1, tzinfo=UTC),
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
