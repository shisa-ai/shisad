"""Adversarial coverage for TOTP approval semantics."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from shisad.core.approval import (
    ApprovalEnvelope,
    ConfirmationLevel,
    ConfirmationMethodLockoutTracker,
    ConfirmationVerificationError,
    TOTPBackend,
    approval_envelope_hash,
    generate_totp_code,
)
from shisad.daemon.handlers._impl import PendingAction
from shisad.security.credentials import ApprovalFactorRecord, InMemoryCredentialStore
from tests.helpers.approval import make_pending_action


def _pending_action(*, confirmation_id: str) -> PendingAction:
    envelope = ApprovalEnvelope(
        approval_id=f"approval-{confirmation_id}",
        pending_action_id=confirmation_id,
        workspace_id="workspace-1",
        daemon_id="daemon-1",
        session_id="session-1",
        required_level="reauthenticated",
        policy_reason="manual",
        action_digest="sha256:test-action",
        nonce="nonce",
        action_summary="test approval",
    )
    # ADV-L4: real ``PendingAction`` (previously ``SimpleNamespace``) so new
    # required dataclass fields surface as test failures, not silent
    # attribute defaults.
    return make_pending_action(
        confirmation_id=confirmation_id,
        user_id="alice",
        tool_name="shell.exec",
        approval_envelope=envelope,
        approval_envelope_hash=approval_envelope_hash(envelope),
        required_level=ConfirmationLevel.REAUTHENTICATED,
        selected_backend_id="totp.default",
        selected_backend_method="totp",
    )


def _backend(tmp_path) -> tuple[TOTPBackend, str]:
    store = InMemoryCredentialStore()
    store.set_approval_store_path(tmp_path / "credentials.json")
    secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    store.register_approval_factor(
        ApprovalFactorRecord(
            credential_id="totp-1",
            user_id="alice",
            method="totp",
            principal_id="ops-laptop",
            secret_b32=secret,
        )
    )
    return TOTPBackend(credential_store=store), secret


def test_expired_totp_code_is_rejected(tmp_path) -> None:
    backend, secret = _backend(tmp_path)
    old_now = datetime(2026, 4, 6, 12, 0, 0, tzinfo=UTC)
    current = old_now + timedelta(minutes=3)
    code = generate_totp_code(secret, now=old_now)

    with pytest.raises(ConfirmationVerificationError, match="invalid_totp_code"):
        backend.verify(
            pending_action=_pending_action(confirmation_id="c-1"),
            params={
                "decision_nonce": "nonce-1",
                "approval_method": "totp",
                "proof": {"totp_code": code},
            },
            now=current,
        )


def test_same_window_totp_reuse_across_pending_actions_is_rejected(tmp_path) -> None:
    backend, secret = _backend(tmp_path)
    now = datetime(2026, 4, 6, 12, 0, 0, tzinfo=UTC)
    code = generate_totp_code(secret, now=now)

    backend.verify(
        pending_action=_pending_action(confirmation_id="c-1"),
        params={
            "decision_nonce": "nonce-1",
            "approval_method": "totp",
            "proof": {"totp_code": code},
        },
        now=now,
    )

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


def test_confirmation_method_lockout_persists_across_restart(tmp_path) -> None:
    state_path = tmp_path / "lockouts.json"
    now = datetime(2026, 4, 6, 12, 0, 0, tzinfo=UTC)
    tracker = ConfirmationMethodLockoutTracker(
        max_failures=3,
        lockout_seconds=60,
        state_path=state_path,
    )
    tracker.record_failure(user_id="alice", method="totp", now=now)
    tracker.record_failure(user_id="alice", method="totp", now=now + timedelta(seconds=1))
    tracker.record_failure(user_id="alice", method="totp", now=now + timedelta(seconds=2))

    reloaded = ConfirmationMethodLockoutTracker(
        max_failures=3,
        lockout_seconds=60,
        state_path=state_path,
    )
    retry_after = reloaded.status(
        user_id="alice",
        method="totp",
        now=now + timedelta(seconds=3),
    )

    assert retry_after is not None
    assert retry_after > 0
