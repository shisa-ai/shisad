"""Adversarial coverage for helper-mediated local FIDO2 approval semantics."""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

from shisad.core.approval import (
    ApprovalEnvelope,
    ConfirmationLevel,
    ConfirmationVerificationError,
    LocalFido2Backend,
    approval_envelope_hash,
)
from shisad.security.credentials import ApprovalFactorRecord, InMemoryCredentialStore
from tests.helpers.webauthn import (
    WebAuthnTestCredential,
    make_authentication_payload,
    make_registration_payload,
)


def _pending_action(
    *,
    confirmation_id: str,
    credential_ids: list[str] | None = None,
    principal_ids: list[str] | None = None,
) -> SimpleNamespace:
    envelope = ApprovalEnvelope(
        approval_id=f"approval-{confirmation_id}",
        pending_action_id=confirmation_id,
        workspace_id="workspace-1",
        daemon_id="daemon-1",
        session_id="session-1",
        required_level=ConfirmationLevel.BOUND_APPROVAL,
        policy_reason="manual",
        action_digest="sha256:test-action",
        nonce="nonce",
        action_summary="test approval",
        allowed_principals=list(principal_ids or []),
        allowed_credentials=list(credential_ids or []),
    )
    return SimpleNamespace(
        confirmation_id=confirmation_id,
        user_id="alice",
        approval_envelope=envelope,
        approval_envelope_hash=approval_envelope_hash(envelope),
        allowed_principals=list(principal_ids or []),
        allowed_credentials=list(credential_ids or []),
        fallback_used=False,
    )


def _registered_backend(
    tmp_path,
) -> tuple[LocalFido2Backend, ApprovalFactorRecord, WebAuthnTestCredential, SimpleNamespace]:
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
        confirmation_id="c-1",
        credential_ids=[factor.credential_id],
        principal_ids=[factor.principal_id],
    )
    return backend, factor, credential, pending


def test_wrong_local_fido2_challenge_is_rejected(tmp_path) -> None:
    backend, _factor, credential, pending = _registered_backend(tmp_path)
    request_options = backend.approval_request_options(pending_action=pending)
    assertion = make_authentication_payload(
        public_key_options=request_options,
        credential=credential,
        challenge_b64url="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    )

    with pytest.raises(ConfirmationVerificationError, match="invalid_webauthn_assertion"):
        backend.verify(
            pending_action=pending,
            params={
                "decision_nonce": "nonce-1",
                "approval_method": "local_fido2",
                "proof": assertion,
            },
        )


def test_local_fido2_assertion_from_unregistered_credential_is_rejected(tmp_path) -> None:
    backend, _factor, _credential, pending = _registered_backend(tmp_path)
    request_options = backend.approval_request_options(pending_action=pending)
    rogue_credential = WebAuthnTestCredential(
        rp_id=backend.rp_id,
        origin=backend.approval_origin,
    )
    assertion = make_authentication_payload(
        public_key_options=request_options,
        credential=rogue_credential,
    )

    with pytest.raises(ConfirmationVerificationError, match="invalid_webauthn_assertion"):
        backend.verify(
            pending_action=pending,
            params={
                "decision_nonce": "nonce-1",
                "approval_method": "local_fido2",
                "proof": assertion,
            },
        )


def test_browser_webauthn_assertion_cannot_satisfy_local_fido2_backend(tmp_path) -> None:
    backend, _factor, _credential, pending = _registered_backend(tmp_path)
    request_options = backend.approval_request_options(pending_action=pending)
    browser_credential = WebAuthnTestCredential(
        rp_id="approve.example.com",
        origin="https://approve.example.com",
    )
    assertion = make_authentication_payload(
        public_key_options=request_options,
        credential=browser_credential,
    )

    with pytest.raises(ConfirmationVerificationError, match="invalid_webauthn_assertion"):
        backend.verify(
            pending_action=pending,
            params={
                "decision_nonce": "nonce-1",
                "approval_method": "local_fido2",
                "proof": assertion,
            },
        )
