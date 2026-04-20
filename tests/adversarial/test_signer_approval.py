"""Adversarial coverage for signer-backed approval semantics."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from shisad.core.approval import (
    ApprovalEnvelope,
    ConfirmationCapabilities,
    ConfirmationLevel,
    ConfirmationRequirement,
    ConfirmationVerificationError,
    EnterpriseKmsSignerBackend,
    IntentAction,
    IntentEnvelope,
    IntentPolicyContext,
    LedgerSignerBackend,
    SignerConfirmationAdapter,
    approval_envelope_hash,
    confirmation_evidence_satisfies_requirement,
    intent_envelope_hash,
)
from shisad.daemon.handlers._impl import PendingAction
from shisad.security.credentials import InMemoryCredentialStore, SignerKeyRecord
from tests.helpers.approval import make_pending_action
from tests.helpers.signer import (
    StubSignerService,
    generate_ed25519_private_key,
    generate_secp256k1_private_key,
    public_key_pem,
)


def _signer_record(*, key_id: str = "kms:finance-primary") -> SignerKeyRecord:
    private_key = generate_ed25519_private_key()
    return SignerKeyRecord(
        credential_id=key_id,
        user_id="alice",
        backend="kms",
        principal_id="finance-owner",
        algorithm="ed25519",
        device_type="ledger-enterprise",
        public_key_pem=public_key_pem(private_key),
    )


def _pending_action(*, key_id: str) -> tuple[PendingAction, dict[str, str]]:
    intent = IntentEnvelope(
        intent_id="intent-1",
        agent_id="daemon-1",
        workspace_id="workspace-1",
        session_id="session-1",
        created_at=datetime(2026, 4, 8, 12, 0, tzinfo=UTC),
        expires_at=datetime(2026, 4, 8, 12, 5, tzinfo=UTC),
        action=IntentAction(
            tool="shell.exec",
            display_summary="Run shell.exec for release verification",
            parameters={"command": ["printf", "ok"]},
            destinations=[],
        ),
        policy_context=IntentPolicyContext(
            required_level=ConfirmationLevel.SIGNED_AUTHORIZATION,
            confirmation_reason="shell.exec requires signer approval",
            matched_rule="shell.exec",
            action_digest="sha256:action",
        ),
        nonce="b64:intent-nonce",
    )
    envelope = ApprovalEnvelope(
        approval_id="approval-1",
        pending_action_id="c-1",
        workspace_id="workspace-1",
        daemon_id="daemon-1",
        session_id="session-1",
        required_level=ConfirmationLevel.SIGNED_AUTHORIZATION,
        policy_reason="shell.exec requires signer approval",
        action_digest="sha256:action",
        allowed_principals=["finance-owner"],
        allowed_credentials=[key_id],
        expires_at=datetime(2026, 4, 8, 12, 5, tzinfo=UTC),
        nonce="b64:approval-nonce",
        intent_envelope_hash=intent_envelope_hash(intent),
        action_summary="Run shell.exec for release verification",
    )
    # ADV-L4: real ``PendingAction`` so new required dataclass fields fail
    # here rather than silently defaulting through ``getattr``.
    pending = make_pending_action(
        confirmation_id="c-1",
        user_id="alice",
        tool_name="shell.exec",
        allowed_principals=["finance-owner"],
        allowed_credentials=[key_id],
        approval_envelope=envelope,
        approval_envelope_hash=approval_envelope_hash(envelope),
        intent_envelope=intent,
        required_level=ConfirmationLevel.SIGNED_AUTHORIZATION,
        selected_backend_id="kms.enterprise",
        selected_backend_method="kms",
    )
    return pending, {"decision_nonce": "nonce", "approval_method": "kms"}


def test_tampered_intent_signature_is_rejected(tmp_path) -> None:
    private_key = generate_ed25519_private_key()
    store = InMemoryCredentialStore()
    store.set_approval_store_path(tmp_path / "approval-factors.json")
    store.register_signer_key(
        SignerKeyRecord(
            credential_id="kms:finance-primary",
            user_id="alice",
            backend="kms",
            principal_id="finance-owner",
            algorithm="ed25519",
            device_type="ledger-enterprise",
            public_key_pem=public_key_pem(private_key),
        )
    )
    pending, params = _pending_action(key_id="kms:finance-primary")
    with StubSignerService(private_key=private_key, tamper_intent=True).run() as signer_url:
        backend = SignerConfirmationAdapter(
            EnterpriseKmsSignerBackend(
                credential_store=store,
                endpoint_url=signer_url,
            )
        )
        with pytest.raises(ConfirmationVerificationError, match="invalid_signer_signature"):
            backend.verify(pending_action=pending, params=params)


def test_blind_sign_evidence_cannot_satisfy_signed_authorization(tmp_path) -> None:
    private_key = generate_ed25519_private_key()
    store = InMemoryCredentialStore()
    store.set_approval_store_path(tmp_path / "approval-factors.json")
    store.register_signer_key(
        SignerKeyRecord(
            credential_id="kms:finance-primary",
            user_id="alice",
            backend="kms",
            principal_id="finance-owner",
            algorithm="ed25519",
            device_type="ledger-enterprise",
            public_key_pem=public_key_pem(private_key),
        )
    )
    pending, params = _pending_action(key_id="kms:finance-primary")
    with StubSignerService(
        private_key=private_key,
        review_surface="opaque_device",
        blind_sign_detected=True,
    ).run() as signer_url:
        backend = SignerConfirmationAdapter(
            EnterpriseKmsSignerBackend(
                credential_store=store,
                endpoint_url=signer_url,
            )
        )
        evidence = backend.verify(pending_action=pending, params=params)
        assert evidence.level == ConfirmationLevel.BOUND_APPROVAL
        assert evidence.blind_sign_detected is True
        assert not confirmation_evidence_satisfies_requirement(
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


def test_provider_ui_signer_cannot_claim_trusted_display(tmp_path) -> None:
    private_key = generate_ed25519_private_key()
    store = InMemoryCredentialStore()
    store.set_approval_store_path(tmp_path / "approval-factors.json")
    store.register_signer_key(
        SignerKeyRecord(
            credential_id="kms:finance-primary",
            user_id="alice",
            backend="kms",
            principal_id="finance-owner",
            algorithm="ed25519",
            device_type="ledger-enterprise",
            public_key_pem=public_key_pem(private_key),
        )
    )
    pending, params = _pending_action(key_id="kms:finance-primary")
    with StubSignerService(
        private_key=private_key,
        review_surface="trusted_device_display",
    ).run() as signer_url:
        backend = SignerConfirmationAdapter(
            EnterpriseKmsSignerBackend(
                credential_store=store,
                endpoint_url=signer_url,
            )
        )
        evidence = backend.verify(pending_action=pending, params=params)
        assert evidence.review_surface == backend.review_surface
        assert evidence.level == ConfirmationLevel.SIGNED_AUTHORIZATION
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


def test_revoked_signer_key_is_rejected(tmp_path) -> None:
    store = InMemoryCredentialStore()
    store.set_approval_store_path(tmp_path / "approval-factors.json")
    record = _signer_record()
    store.register_signer_key(record)
    assert store.revoke_signer_key(credential_id=record.credential_id) == 1
    pending, params = _pending_action(key_id=record.credential_id)
    backend = SignerConfirmationAdapter(
        EnterpriseKmsSignerBackend(
            credential_store=store,
            endpoint_url="http://127.0.0.1:9/sign",
            request_timeout=timedelta(seconds=1),
        )
    )
    with pytest.raises(ConfirmationVerificationError, match="signer_key_revoked"):
        backend.verify(pending_action=pending, params=params)


def test_allowed_signer_set_prefers_active_key_over_revoked_peer(tmp_path) -> None:
    active_private_key = generate_ed25519_private_key()
    revoked_private_key = generate_ed25519_private_key()
    store = InMemoryCredentialStore()
    store.set_approval_store_path(tmp_path / "approval-factors.json")
    store.register_signer_key(
        SignerKeyRecord(
            credential_id="kms:finance-primary",
            user_id="alice",
            backend="kms",
            principal_id="finance-owner",
            algorithm="ed25519",
            device_type="ledger-enterprise",
            public_key_pem=public_key_pem(active_private_key),
        )
    )
    store.register_signer_key(
        SignerKeyRecord(
            credential_id="kms:finance-backup",
            user_id="alice",
            backend="kms",
            principal_id="finance-owner",
            algorithm="ed25519",
            device_type="ledger-enterprise",
            public_key_pem=public_key_pem(revoked_private_key),
        )
    )
    assert store.revoke_signer_key(credential_id="kms:finance-backup") == 1
    pending, params = _pending_action(key_id="kms:finance-primary")
    allowed_credentials = ["kms:finance-primary", "kms:finance-backup"]
    pending.allowed_credentials = allowed_credentials
    pending.approval_envelope = pending.approval_envelope.model_copy(
        update={"allowed_credentials": allowed_credentials}
    )
    with StubSignerService(private_key=active_private_key).run() as signer_url:
        backend = SignerConfirmationAdapter(
            EnterpriseKmsSignerBackend(
                credential_store=store,
                endpoint_url=signer_url,
            )
        )
        evidence = backend.verify(pending_action=pending, params=params)
        assert evidence.credential_id == "kms:finance-primary"


def test_malformed_signer_timestamp_fails_closed(tmp_path) -> None:
    private_key = generate_ed25519_private_key()
    store = InMemoryCredentialStore()
    store.set_approval_store_path(tmp_path / "approval-factors.json")
    store.register_signer_key(
        SignerKeyRecord(
            credential_id="kms:finance-primary",
            user_id="alice",
            backend="kms",
            principal_id="finance-owner",
            algorithm="ed25519",
            device_type="ledger-enterprise",
            public_key_pem=public_key_pem(private_key),
        )
    )
    pending, params = _pending_action(key_id="kms:finance-primary")
    with StubSignerService(
        private_key=private_key,
        signed_at_override="not-a-timestamp",
    ).run() as signer_url:
        backend = SignerConfirmationAdapter(
            EnterpriseKmsSignerBackend(
                credential_store=store,
                endpoint_url=signer_url,
            )
        )
        with pytest.raises(ConfirmationVerificationError, match="signer_backend_invalid_response"):
            backend.verify(pending_action=pending, params=params)


# ---------------------------------------------------------------------------
# Ledger signer backend (L4 trusted-display) adversarial tests
# ---------------------------------------------------------------------------


def _ledger_pending_action(
    *, key_id: str
) -> tuple[PendingAction, dict[str, str]]:
    intent = IntentEnvelope(
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
    envelope = ApprovalEnvelope(
        approval_id="approval-ledger-1",
        pending_action_id="c-ledger-1",
        workspace_id="workspace-1",
        daemon_id="daemon-1",
        session_id="session-1",
        required_level=ConfirmationLevel.TRUSTED_DISPLAY_AUTHORIZATION,
        policy_reason="deploy.production requires trusted-display",
        action_digest="sha256:action-ledger",
        allowed_principals=["ops-owner"],
        allowed_credentials=[key_id],
        expires_at=datetime(2026, 4, 10, 12, 5, tzinfo=UTC),
        nonce="b64:approval-nonce-ledger",
        intent_envelope_hash=intent_envelope_hash(intent),
        action_summary="Deploy v2.1.0 to production cluster",
    )
    pending = make_pending_action(
        confirmation_id="c-ledger-1",
        user_id="alice",
        tool_name="deploy.production",
        arguments={"version": "2.1.0", "target": "prod"},
        allowed_principals=["ops-owner"],
        allowed_credentials=[key_id],
        approval_envelope=envelope,
        approval_envelope_hash=approval_envelope_hash(envelope),
        intent_envelope=intent,
        required_level=ConfirmationLevel.TRUSTED_DISPLAY_AUTHORIZATION,
        selected_backend_id="ledger.default",
        selected_backend_method="ledger",
        fallback_used=False,
    )
    return pending, {"decision_nonce": "nonce", "approval_method": "ledger"}


def test_ledger_trusted_display_with_valid_signature(tmp_path) -> None:
    private_key = generate_secp256k1_private_key()
    store = InMemoryCredentialStore()
    store.set_approval_store_path(tmp_path / "approval-factors.json")
    store.register_signer_key(
        SignerKeyRecord(
            credential_id="ledger:stax-1",
            user_id="alice",
            backend="ledger",
            principal_id="ops-owner",
            algorithm="ecdsa-secp256k1",
            device_type="ledger-consumer",
            public_key_pem=public_key_pem(private_key),
            signing_scheme="eip712",
        )
    )
    pending, params = _ledger_pending_action(key_id="ledger:stax-1")
    with StubSignerService(
        private_key=private_key,
        algorithm="eip712",
        review_surface="trusted_device_display",
    ).run() as signer_url:
        backend = SignerConfirmationAdapter(
            LedgerSignerBackend(
                credential_store=store,
                endpoint_url=signer_url,
            )
        )
        evidence = backend.verify(pending_action=pending, params=params)
        assert evidence.level == ConfirmationLevel.TRUSTED_DISPLAY_AUTHORIZATION
        assert evidence.review_surface.value == "trusted_device_display"
        assert evidence.blind_sign_detected is False


def test_ledger_blind_sign_drops_to_bound_approval(tmp_path) -> None:
    private_key = generate_secp256k1_private_key()
    store = InMemoryCredentialStore()
    store.set_approval_store_path(tmp_path / "approval-factors.json")
    store.register_signer_key(
        SignerKeyRecord(
            credential_id="ledger:stax-1",
            user_id="alice",
            backend="ledger",
            principal_id="ops-owner",
            algorithm="ecdsa-secp256k1",
            device_type="ledger-consumer",
            public_key_pem=public_key_pem(private_key),
            signing_scheme="eip712",
        )
    )
    pending, params = _ledger_pending_action(key_id="ledger:stax-1")
    with StubSignerService(
        private_key=private_key,
        algorithm="eip712",
        review_surface="opaque_device",
        blind_sign_detected=True,
    ).run() as signer_url:
        backend = SignerConfirmationAdapter(
            LedgerSignerBackend(
                credential_store=store,
                endpoint_url=signer_url,
            )
        )
        evidence = backend.verify(pending_action=pending, params=params)
        assert evidence.level == ConfirmationLevel.BOUND_APPROVAL
        assert evidence.blind_sign_detected is True
        assert not confirmation_evidence_satisfies_requirement(
            requirement=ConfirmationRequirement(
                level=ConfirmationLevel.TRUSTED_DISPLAY_AUTHORIZATION,
                methods=["ledger"],
                allowed_principals=["ops-owner"],
                allowed_credentials=["ledger:stax-1"],
                require_capabilities=ConfirmationCapabilities(
                    principal_binding=True,
                    full_intent_signature=True,
                    trusted_display=True,
                ),
            ),
            evidence=evidence,
            backend=backend,
        )


def test_ledger_tampered_intent_rejected(tmp_path) -> None:
    private_key = generate_secp256k1_private_key()
    store = InMemoryCredentialStore()
    store.set_approval_store_path(tmp_path / "approval-factors.json")
    store.register_signer_key(
        SignerKeyRecord(
            credential_id="ledger:stax-1",
            user_id="alice",
            backend="ledger",
            principal_id="ops-owner",
            algorithm="ecdsa-secp256k1",
            device_type="ledger-consumer",
            public_key_pem=public_key_pem(private_key),
            signing_scheme="eip712",
        )
    )
    pending, params = _ledger_pending_action(key_id="ledger:stax-1")
    with StubSignerService(
        private_key=private_key,
        algorithm="eip712",
        review_surface="trusted_device_display",
        tamper_intent=True,
    ).run() as signer_url:
        backend = SignerConfirmationAdapter(
            LedgerSignerBackend(
                credential_store=store,
                endpoint_url=signer_url,
            )
        )
        with pytest.raises(
            ConfirmationVerificationError, match="invalid_signer_signature"
        ):
            backend.verify(pending_action=pending, params=params)


def test_ledger_opaque_device_drops_below_signed_authorization(tmp_path) -> None:
    private_key = generate_secp256k1_private_key()
    store = InMemoryCredentialStore()
    store.set_approval_store_path(tmp_path / "approval-factors.json")
    store.register_signer_key(
        SignerKeyRecord(
            credential_id="ledger:stax-1",
            user_id="alice",
            backend="ledger",
            principal_id="ops-owner",
            algorithm="ecdsa-secp256k1",
            device_type="ledger-consumer",
            public_key_pem=public_key_pem(private_key),
            signing_scheme="eip712",
        )
    )
    pending, params = _ledger_pending_action(key_id="ledger:stax-1")
    with StubSignerService(
        private_key=private_key,
        algorithm="eip712",
        review_surface="opaque_device",
        blind_sign_detected=False,
    ).run() as signer_url:
        backend = SignerConfirmationAdapter(
            LedgerSignerBackend(
                credential_store=store,
                endpoint_url=signer_url,
            )
        )
        evidence = backend.verify(pending_action=pending, params=params)
        assert evidence.level == ConfirmationLevel.BOUND_APPROVAL
