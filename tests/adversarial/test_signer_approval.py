"""Adversarial coverage for signer-backed approval semantics."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

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
    SignerConfirmationAdapter,
    approval_envelope_hash,
    confirmation_evidence_satisfies_requirement,
    intent_envelope_hash,
)
from shisad.security.credentials import InMemoryCredentialStore, SignerKeyRecord
from tests.helpers.signer import StubSignerService, generate_ed25519_private_key, public_key_pem


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


def _pending_action(*, key_id: str) -> tuple[SimpleNamespace, dict[str, str]]:
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
    pending = SimpleNamespace(
        confirmation_id="c-1",
        user_id="alice",
        allowed_principals=["finance-owner"],
        allowed_credentials=[key_id],
        approval_envelope=envelope,
        approval_envelope_hash=approval_envelope_hash(envelope),
        intent_envelope=intent,
        fallback_used=False,
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
