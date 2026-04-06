"""Adversarial coverage for WebAuthn approval semantics and HTTP ceremony hardening."""

from __future__ import annotations

import asyncio
import json
import socket
import urllib.error
import urllib.request
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import pytest

from shisad.core.approval import (
    ApprovalEnvelope,
    ConfirmationVerificationError,
    WebAuthnBackend,
    approval_envelope_hash,
)
from shisad.core.types import ToolName
from shisad.daemon.approval_web import ApprovalWebService
from shisad.security.credentials import ApprovalFactorRecord, InMemoryCredentialStore
from tests.helpers.webauthn import (
    WebAuthnTestCredential,
    make_authentication_payload,
    make_registration_payload,
)


def _reserve_local_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _http_post_json(url: str, payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=5.0) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8")
        return exc.code, json.loads(body) if body else {}


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
        required_level="bound_approval",
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
        tool_name=ToolName("shell.exec"),
        approval_envelope=envelope,
        approval_envelope_hash=approval_envelope_hash(envelope),
        allowed_principals=list(principal_ids or []),
        allowed_credentials=list(credential_ids or []),
        fallback_used=False,
    )


def _registered_backend(
    tmp_path,
) -> tuple[WebAuthnBackend, ApprovalFactorRecord, WebAuthnTestCredential, SimpleNamespace]:
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
    return backend, factor, credential, pending


def test_wrong_webauthn_challenge_is_rejected(tmp_path) -> None:
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
                "approval_method": "webauthn",
                "proof": assertion,
            },
        )


def test_assertion_from_unregistered_credential_is_rejected(tmp_path) -> None:
    backend, _factor, _credential, pending = _registered_backend(tmp_path)
    request_options = backend.approval_request_options(pending_action=pending)
    rogue_credential = WebAuthnTestCredential(
        rp_id="approve.example.com",
        origin="https://approve.example.com",
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
                "approval_method": "webauthn",
                "proof": assertion,
            },
        )


@pytest.mark.asyncio
async def test_expired_approval_result_is_returned_as_gone() -> None:
    port = _reserve_local_port()
    service = ApprovalWebService(
        origin=f"http://127.0.0.1:{port}",
        bind_host="127.0.0.1",
        bind_port=port,
        link_ttl_seconds=600,
        rate_limit_window_seconds=60,
        rate_limit_max_attempts=2,
    )

    async def _context(_target_id: str) -> dict[str, Any]:
        return {"ok": True, "public_key": {"challenge": "abc"}}

    async def _expired(_target_id: str, _payload: dict[str, Any]) -> dict[str, Any]:
        return {"confirmed": False, "reason": "approval_expired"}

    loop = asyncio.get_running_loop()
    service.bind_callbacks(
        loop=loop,
        registration_context=_context,
        registration_complete=_expired,
        approval_context=_context,
        approval_complete=_expired,
    )
    await service.start()
    try:
        approval_url = service.issue_approval_link("c-1")
        status_code, payload = await asyncio.to_thread(_http_post_json, approval_url, {})
        assert status_code == 410
        assert payload["reason"] == "approval_expired"
    finally:
        await service.stop()


@pytest.mark.asyncio
async def test_approval_post_rate_limit_rejects_repeated_attempts() -> None:
    port = _reserve_local_port()
    service = ApprovalWebService(
        origin=f"http://127.0.0.1:{port}",
        bind_host="127.0.0.1",
        bind_port=port,
        link_ttl_seconds=600,
        rate_limit_window_seconds=60,
        rate_limit_max_attempts=1,
    )

    async def _context(_target_id: str) -> dict[str, Any]:
        return {"ok": True, "public_key": {"challenge": "abc"}}

    async def _invalid(_target_id: str, _payload: dict[str, Any]) -> dict[str, Any]:
        return {"confirmed": False, "reason": "invalid_webauthn_assertion"}

    loop = asyncio.get_running_loop()
    service.bind_callbacks(
        loop=loop,
        registration_context=_context,
        registration_complete=_invalid,
        approval_context=_context,
        approval_complete=_invalid,
    )
    await service.start()
    try:
        approval_url = service.issue_approval_link("c-1")
        first_status, first_payload = await asyncio.to_thread(_http_post_json, approval_url, {})
        second_status, second_payload = await asyncio.to_thread(_http_post_json, approval_url, {})
        assert first_status == 400
        assert first_payload["reason"] == "invalid_webauthn_assertion"
        assert second_status == 429
        assert second_payload["reason"] == "rate_limited"
    finally:
        await service.stop()
