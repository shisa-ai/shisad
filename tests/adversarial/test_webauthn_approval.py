"""Adversarial coverage for WebAuthn approval semantics and HTTP ceremony hardening."""

from __future__ import annotations

import asyncio
import json
import logging
import re
import socket
import urllib.error
import urllib.request
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import pytest

import shisad.daemon.approval_web as approval_web_module
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


def _http_post_bytes(
    url: str,
    payload: bytes,
    *,
    content_type: str = "application/json",
) -> tuple[int, dict[str, Any]]:
    request = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": content_type},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=5.0) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8")
        return exc.code, json.loads(body) if body else {}


def _http_get(url: str) -> tuple[int, dict[str, str], str]:
    request = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=5.0) as response:
            return (
                response.status,
                dict(response.headers.items()),
                response.read().decode("utf-8"),
            )
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers.items()), exc.read().decode("utf-8")


def _http_get_json(url: str) -> tuple[int, dict[str, Any]]:
    status_code, _headers, body = _http_get(url)
    return status_code, json.loads(body) if body else {}


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


@pytest.mark.asyncio
async def test_ceremony_page_sets_security_headers_and_escapes_inline_json() -> None:
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
        return {
            "ok": True,
            "summary": "test approval",
            "public_key": {
                "challenge": "abc",
                "user": {
                    "id": "dXNlcg",
                    "name": 'alice</script><script>alert("pwned")</script>',
                    "displayName": "ops-phone",
                },
            },
        }

    async def _complete(_target_id: str, _payload: dict[str, Any]) -> dict[str, Any]:
        return {"confirmed": False, "reason": "invalid_webauthn_assertion"}

    loop = asyncio.get_running_loop()
    service.bind_callbacks(
        loop=loop,
        registration_context=_context,
        registration_complete=_complete,
        approval_context=_context,
        approval_complete=_complete,
    )
    await service.start()
    try:
        approval_url = service.issue_approval_link("c-1")
        status_code, headers, body = await asyncio.to_thread(_http_get, approval_url)
        assert status_code == 200
        assert headers["Cache-Control"] == "no-store"
        assert headers["Content-Security-Policy"] == (
            "default-src 'none'; script-src 'unsafe-inline'; connect-src 'self'; "
            "style-src 'unsafe-inline'; frame-ancestors 'none'"
        )
        assert headers["Referrer-Policy"] == "no-referrer"
        assert headers["X-Content-Type-Options"] == "nosniff"
        assert headers["X-Frame-Options"] == "DENY"
        assert '</script><script>alert("pwned")</script>' not in body
        assert '<\\/script><script>alert(\\"pwned\\")<\\/script>' in body
    finally:
        await service.stop()


@pytest.mark.asyncio
async def test_approval_post_rejects_oversized_body_without_consuming_token() -> None:
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

    async def _complete(_target_id: str, _payload: dict[str, Any]) -> dict[str, Any]:
        return {"confirmed": False, "reason": "invalid_webauthn_assertion"}

    loop = asyncio.get_running_loop()
    service.bind_callbacks(
        loop=loop,
        registration_context=_context,
        registration_complete=_complete,
        approval_context=_context,
        approval_complete=_complete,
    )
    await service.start()
    try:
        approval_url = service.issue_approval_link("c-1")
        status_code, payload = await asyncio.to_thread(
            _http_post_bytes,
            approval_url,
            b"{" + (b"x" * (70 * 1024)),
        )
        assert status_code == 413
        assert payload["reason"] == "payload_too_large"
        assert service.issue_approval_link("c-1") == approval_url
    finally:
        await service.stop()


@pytest.mark.asyncio
async def test_approval_token_claim_blocks_concurrent_reuse_and_reuses_same_link() -> None:
    port = _reserve_local_port()
    service = ApprovalWebService(
        origin=f"http://127.0.0.1:{port}",
        bind_host="127.0.0.1",
        bind_port=port,
        link_ttl_seconds=600,
        rate_limit_window_seconds=60,
        rate_limit_max_attempts=3,
    )
    callback_started = asyncio.Event()
    release_callback = asyncio.Event()

    async def _context(_target_id: str) -> dict[str, Any]:
        return {"ok": True, "public_key": {"challenge": "abc"}}

    async def _complete(_target_id: str, _payload: dict[str, Any]) -> dict[str, Any]:
        callback_started.set()
        await release_callback.wait()
        return {"confirmed": False, "reason": "invalid_webauthn_assertion"}

    loop = asyncio.get_running_loop()
    service.bind_callbacks(
        loop=loop,
        registration_context=_context,
        registration_complete=_complete,
        approval_context=_context,
        approval_complete=_complete,
    )
    await service.start()
    try:
        approval_url = service.issue_approval_link("c-1")
        assert service.issue_approval_link("c-1") == approval_url

        first_attempt = asyncio.create_task(asyncio.to_thread(_http_post_json, approval_url, {}))
        await callback_started.wait()
        second_status, second_payload = await asyncio.to_thread(_http_post_json, approval_url, {})
        release_callback.set()
        first_status, first_payload = await first_attempt
        third_status, third_payload = await asyncio.to_thread(_http_post_json, approval_url, {})

        assert second_status == 403
        assert second_payload["reason"] == "invalid_or_expired_token"
        assert first_status == 400
        assert first_payload["reason"] == "invalid_webauthn_assertion"
        assert third_status == 400
        assert third_payload["reason"] == "invalid_webauthn_assertion"
        assert service.issue_approval_link("c-1") == approval_url
    finally:
        await service.stop()


@pytest.mark.asyncio
async def test_approval_callback_timeout_returns_503_and_keeps_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
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

    async def _slow_complete(_target_id: str, _payload: dict[str, Any]) -> dict[str, Any]:
        await asyncio.sleep(0.05)
        return {"confirmed": True}

    monkeypatch.setattr(approval_web_module, "_COMPLETE_CALLBACK_TIMEOUT_SECONDS", 0.01)
    loop = asyncio.get_running_loop()
    service.bind_callbacks(
        loop=loop,
        registration_context=_context,
        registration_complete=_slow_complete,
        approval_context=_context,
        approval_complete=_slow_complete,
    )
    await service.start()
    try:
        approval_url = service.issue_approval_link("c-1")
        status_code, payload = await asyncio.to_thread(_http_post_json, approval_url, {})
        assert status_code == 503
        assert payload["reason"] == "approval_web_callback_timeout"
        assert service.issue_approval_link("c-1") == approval_url
    finally:
        await service.stop()


@pytest.mark.parametrize(
    "request_line",
    [
        "GET /approve/c-1?token=sabcdef HTTP/1.1",
        "GET /approve/c-1?token=abcsdef&format=json HTTP/1.1",
    ],
)
def test_approval_web_redact_log_text_redacts_entire_token(request_line: str) -> None:
    redacted = ApprovalWebService._redact_log_text(request_line)

    assert "sabcdef" not in redacted
    assert "abcsdef" not in redacted
    assert re.search(r"token=redacted(?:[&\s\"']|$)", redacted)


@pytest.mark.asyncio
async def test_approval_web_access_logs_redact_tokens(
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
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

    async def _complete(_target_id: str, _payload: dict[str, Any]) -> dict[str, Any]:
        return {"confirmed": False, "reason": "invalid_webauthn_assertion"}

    loop = asyncio.get_running_loop()
    service.bind_callbacks(
        loop=loop,
        registration_context=_context,
        registration_complete=_complete,
        approval_context=_context,
        approval_complete=_complete,
    )
    await service.start()
    try:
        caplog.set_level(logging.INFO, logger="shisad.daemon.approval_web")
        caplog.clear()
        monkeypatch.setattr(approval_web_module.secrets, "token_urlsafe", lambda *_args: "abcsdef")
        approval_url = service.issue_approval_link("c-1")
        await asyncio.to_thread(_http_get, approval_url)
        assert "abcsdef" not in caplog.text
        assert re.search(r"token=redacted(?:[&\s\"']|$)", caplog.text)
    finally:
        await service.stop()


@pytest.mark.asyncio
async def test_ipv6_loopback_approval_listener_starts_when_supported() -> None:
    if not socket.has_ipv6:
        pytest.skip("IPv6 is unavailable on this platform")
    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as probe:
        try:
            probe.bind(("::1", 0))
        except OSError:
            pytest.skip("IPv6 loopback is unavailable on this platform")
        port = int(probe.getsockname()[1])

    service = ApprovalWebService(
        origin=f"http://[::1]:{port}",
        bind_host="::1",
        bind_port=port,
        link_ttl_seconds=600,
        rate_limit_window_seconds=60,
        rate_limit_max_attempts=2,
    )

    async def _context(_target_id: str) -> dict[str, Any]:
        return {"ok": True, "public_key": {"challenge": "abc"}}

    async def _complete(_target_id: str, _payload: dict[str, Any]) -> dict[str, Any]:
        return {"confirmed": False, "reason": "invalid_webauthn_assertion"}

    loop = asyncio.get_running_loop()
    service.bind_callbacks(
        loop=loop,
        registration_context=_context,
        registration_complete=_complete,
        approval_context=_context,
        approval_complete=_complete,
    )
    await service.start()
    try:
        approval_url = service.issue_approval_link("c-1")
        status_code, payload = await asyncio.to_thread(
            _http_get_json, f"{approval_url}&format=json"
        )
        assert status_code == 200
        assert payload["ok"] is True
    finally:
        await service.stop()
