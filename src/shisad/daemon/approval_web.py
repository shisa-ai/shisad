"""Daemon-owned HTTP surface for WebAuthn registration and approval ceremonies."""

from __future__ import annotations

import asyncio
import html
import json
import logging
import secrets
import threading
import time
from collections import defaultdict, deque
from collections.abc import Callable, Coroutine
from concurrent.futures import Future
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Literal, cast
from urllib.parse import parse_qs, quote, urlparse

import qrcode  # type: ignore[import-untyped]

logger = logging.getLogger(__name__)

_ContextCallback = Callable[[str], Coroutine[Any, Any, dict[str, Any]]]
_CompleteCallback = Callable[[str, dict[str, Any]], Coroutine[Any, Any, dict[str, Any]]]


@dataclass(frozen=True, slots=True)
class _CeremonyToken:
    kind: Literal["approve", "register"]
    target_id: str
    expires_at: datetime


class ApprovalWebService:
    """Small HTTP server that hosts browser-first approval ceremonies."""

    def __init__(
        self,
        *,
        origin: str,
        bind_host: str,
        bind_port: int,
        link_ttl_seconds: int,
        rate_limit_window_seconds: int,
        rate_limit_max_attempts: int,
    ) -> None:
        self.origin = origin.rstrip("/")
        self.bind_host = bind_host.strip() or "127.0.0.1"
        self.bind_port = int(bind_port)
        self.link_ttl_seconds = max(60, int(link_ttl_seconds))
        self.rate_limit_window_seconds = max(1, int(rate_limit_window_seconds))
        self.rate_limit_max_attempts = max(1, int(rate_limit_max_attempts))
        self.enabled = bool(self.origin)

        self._loop: asyncio.AbstractEventLoop | None = None
        self._registration_context_cb: _ContextCallback | None = None
        self._registration_complete_cb: _CompleteCallback | None = None
        self._approval_context_cb: _ContextCallback | None = None
        self._approval_complete_cb: _CompleteCallback | None = None

        self._lock = threading.Lock()
        self._tokens: dict[str, _CeremonyToken] = {}
        self._attempts: dict[str, deque[float]] = defaultdict(deque)
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    def bind_callbacks(
        self,
        *,
        loop: asyncio.AbstractEventLoop,
        registration_context: _ContextCallback,
        registration_complete: _CompleteCallback,
        approval_context: _ContextCallback,
        approval_complete: _CompleteCallback,
    ) -> None:
        self._loop = loop
        self._registration_context_cb = registration_context
        self._registration_complete_cb = registration_complete
        self._approval_context_cb = approval_context
        self._approval_complete_cb = approval_complete

    async def start(self) -> None:
        if not self.enabled or self._server is not None:
            return
        service = self

        class _Handler(BaseHTTPRequestHandler):
            server_version = "shisad-approval/0.1"
            sys_version = ""

            def do_GET(self) -> None:
                service._handle_http(self)

            def do_POST(self) -> None:
                service._handle_http(self)

            def log_message(self, format: str, *args: object) -> None:
                logger.info("approval-web %s", format % args)

        self._server = ThreadingHTTPServer((self.bind_host, self.bind_port), _Handler)
        self.bind_port = int(self._server.server_port)
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            kwargs={"poll_interval": 0.2},
            name="shisad-approval-web",
            daemon=True,
        )
        self._thread.start()
        logger.info(
            "Approval web listener started on http://%s:%d (public origin: %s)",
            self.bind_host,
            self.bind_port,
            self.origin,
        )

    async def stop(self) -> None:
        server = self._server
        if server is None:
            return
        thread = self._thread
        self._server = None
        self._thread = None
        await asyncio.to_thread(server.shutdown)
        await asyncio.to_thread(server.server_close)
        if thread is not None:
            await asyncio.to_thread(thread.join, 2.0)

    def issue_approval_link(self, confirmation_id: str) -> str:
        return self._issue_link("approve", confirmation_id)

    def issue_registration_link(self, enrollment_id: str) -> str:
        return self._issue_link("register", enrollment_id)

    def qr_ascii(self, url: str) -> str:
        if not url:
            return ""
        qr = qrcode.QRCode(border=1)
        qr.add_data(url)
        qr.make(fit=True)
        matrix = qr.get_matrix()
        return "\n".join(
            "".join("##" if cell else "  " for cell in row)
            for row in matrix
        )

    def _issue_link(self, kind: Literal["approve", "register"], target_id: str) -> str:
        if not self.enabled or not target_id.strip():
            return ""
        self._prune_state()
        token = secrets.token_urlsafe(32)
        with self._lock:
            self._tokens[token] = _CeremonyToken(
                kind=kind,
                target_id=target_id.strip(),
                expires_at=datetime.now(UTC) + timedelta(seconds=self.link_ttl_seconds),
            )
        return f"{self.origin}/{kind}/{quote(target_id.strip())}?token={quote(token)}"

    def _handle_http(self, handler: BaseHTTPRequestHandler) -> None:
        parsed = urlparse(handler.path)
        parts = [part for part in parsed.path.split("/") if part]
        if len(parts) != 2 or parts[0] not in {"approve", "register"}:
            self._send_json(
                handler,
                HTTPStatus.NOT_FOUND,
                {"ok": False, "reason": "not_found"},
            )
            return

        kind = cast(Literal["approve", "register"], parts[0])
        target_id = parts[1]
        query = parse_qs(parsed.query)
        token = str(query.get("token", [""])[0]).strip()
        fmt = str(query.get("format", [""])[0]).strip().lower()
        if not self._validate_token(token=token, kind=kind, target_id=target_id):
            self._send_json(
                handler,
                HTTPStatus.FORBIDDEN,
                {"ok": False, "reason": "invalid_or_expired_token"},
            )
            return

        if handler.command == "GET":
            self._handle_get(handler, kind=kind, target_id=target_id, token=token, fmt=fmt)
            return
        if handler.command == "POST":
            self._handle_post(handler, kind=kind, target_id=target_id, token=token)
            return

        self._send_json(
            handler,
            HTTPStatus.METHOD_NOT_ALLOWED,
            {"ok": False, "reason": "method_not_allowed"},
        )

    def _handle_get(
        self,
        handler: BaseHTTPRequestHandler,
        *,
        kind: Literal["approve", "register"],
        target_id: str,
        token: str,
        fmt: str,
    ) -> None:
        callback = (
            self._approval_context_cb if kind == "approve" else self._registration_context_cb
        )
        context = self._call_callback(callback, target_id)
        if fmt == "json":
            self._send_json(handler, HTTPStatus.OK, context)
            return
        post_url = f"/{kind}/{quote(target_id)}?token={quote(token)}"
        if kind == "approve":
            body = self._render_approval_page(context, post_url=post_url)
        else:
            body = self._render_registration_page(context, post_url=post_url)
        self._send_html(handler, HTTPStatus.OK, body)

    def _handle_post(
        self,
        handler: BaseHTTPRequestHandler,
        *,
        kind: Literal["approve", "register"],
        target_id: str,
        token: str,
    ) -> None:
        if not self._register_attempt(token):
            self._send_json(
                handler,
                HTTPStatus.TOO_MANY_REQUESTS,
                {"ok": False, "reason": "rate_limited"},
            )
            return

        try:
            length = int(handler.headers.get("Content-Length", "0") or 0)
        except ValueError:
            length = 0
        raw_body = handler.rfile.read(max(0, length))
        try:
            payload = json.loads(raw_body.decode("utf-8")) if raw_body else {}
        except json.JSONDecodeError:
            self._send_json(
                handler,
                HTTPStatus.BAD_REQUEST,
                {"ok": False, "reason": "invalid_json"},
            )
            return
        if not isinstance(payload, dict):
            self._send_json(
                handler,
                HTTPStatus.BAD_REQUEST,
                {"ok": False, "reason": "invalid_json"},
            )
            return

        callback = (
            self._approval_complete_cb if kind == "approve" else self._registration_complete_cb
        )
        result = self._call_complete_callback(callback, target_id, payload)
        status = self._status_for_result(result)
        if status == HTTPStatus.OK:
            self._consume_token(token)
        self._send_json(handler, status, result)

    def _call_callback(
        self,
        callback: _ContextCallback | None,
        target_id: str,
    ) -> dict[str, Any]:
        if callback is None or self._loop is None:
            return {"ok": False, "reason": "approval_web_not_ready"}
        future: Future[dict[str, Any]] = asyncio.run_coroutine_threadsafe(
            callback(target_id),
            self._loop,
        )
        return dict(future.result(timeout=15.0))

    def _call_complete_callback(
        self,
        callback: _CompleteCallback | None,
        target_id: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        if callback is None or self._loop is None:
            return {"ok": False, "reason": "approval_web_not_ready"}
        future: Future[dict[str, Any]] = asyncio.run_coroutine_threadsafe(
            callback(target_id, payload),
            self._loop,
        )
        return dict(future.result(timeout=20.0))

    def _validate_token(
        self,
        *,
        token: str,
        kind: Literal["approve", "register"],
        target_id: str,
    ) -> bool:
        self._prune_state()
        with self._lock:
            candidate = self._tokens.get(token)
        if candidate is None:
            return False
        if candidate.kind != kind or candidate.target_id != target_id:
            return False
        return candidate.expires_at > datetime.now(UTC)

    def _consume_token(self, token: str) -> None:
        with self._lock:
            self._tokens.pop(token, None)
            self._attempts.pop(token, None)

    def _register_attempt(self, token: str) -> bool:
        now = time.monotonic()
        self._prune_state(now_monotonic=now)
        with self._lock:
            attempts = self._attempts[token]
            while attempts and now - attempts[0] > self.rate_limit_window_seconds:
                attempts.popleft()
            if len(attempts) >= self.rate_limit_max_attempts:
                return False
            attempts.append(now)
        return True

    def _prune_state(self, *, now_monotonic: float | None = None) -> None:
        current = datetime.now(UTC)
        monotonic_now = time.monotonic() if now_monotonic is None else now_monotonic
        with self._lock:
            expired_tokens = [
                token for token, item in self._tokens.items() if item.expires_at <= current
            ]
            for token in expired_tokens:
                self._tokens.pop(token, None)
                self._attempts.pop(token, None)
            expired_attempt_keys = []
            for token, attempts in self._attempts.items():
                while attempts and monotonic_now - attempts[0] > self.rate_limit_window_seconds:
                    attempts.popleft()
                if not attempts:
                    expired_attempt_keys.append(token)
            for token in expired_attempt_keys:
                self._attempts.pop(token, None)

    @staticmethod
    def _status_for_result(result: dict[str, Any]) -> HTTPStatus:
        if (
            bool(result.get("confirmed"))
            or bool(result.get("registered"))
            or bool(result.get("ok"))
        ):
            return HTTPStatus.OK
        reason = str(result.get("reason") or result.get("status") or "").strip().lower()
        if reason in {"not_found", "enrollment_not_found"}:
            return HTTPStatus.NOT_FOUND
        if reason in {"approval_expired", "enrollment_expired"}:
            return HTTPStatus.GONE
        if reason == "rate_limited":
            return HTTPStatus.TOO_MANY_REQUESTS
        return HTTPStatus.BAD_REQUEST

    @staticmethod
    def _send_json(
        handler: BaseHTTPRequestHandler,
        status: HTTPStatus,
        payload: dict[str, Any],
    ) -> None:
        encoded = json.dumps(payload, sort_keys=True).encode("utf-8")
        handler.send_response(int(status))
        handler.send_header("Content-Type", "application/json; charset=utf-8")
        handler.send_header("Content-Length", str(len(encoded)))
        handler.end_headers()
        handler.wfile.write(encoded)

    @staticmethod
    def _send_html(handler: BaseHTTPRequestHandler, status: HTTPStatus, body: str) -> None:
        encoded = body.encode("utf-8")
        handler.send_response(int(status))
        handler.send_header("Content-Type", "text/html; charset=utf-8")
        handler.send_header("Content-Length", str(len(encoded)))
        handler.end_headers()
        handler.wfile.write(encoded)

    def _render_approval_page(self, context: dict[str, Any], *, post_url: str) -> str:
        title = "Approve Action"
        intro = "Open this page in a system browser and approve with your passkey."
        return self._render_page(
            title=title,
            intro=intro,
            button_label="Approve With Passkey",
            post_url=post_url,
            context=context,
            ceremony="approve",
        )

    def _render_registration_page(self, context: dict[str, Any], *, post_url: str) -> str:
        title = "Register Passkey"
        intro = "Open this page in a system browser and register a new passkey."
        return self._render_page(
            title=title,
            intro=intro,
            button_label="Register Passkey",
            post_url=post_url,
            context=context,
            ceremony="register",
        )

    def _render_page(
        self,
        *,
        title: str,
        intro: str,
        button_label: str,
        post_url: str,
        context: dict[str, Any],
        ceremony: Literal["approve", "register"],
    ) -> str:
        escaped_title = html.escape(title)
        escaped_intro = html.escape(intro)
        pretty_context = html.escape(str(context.get("summary") or context.get("message") or ""))
        options_json = json.dumps(context.get("public_key") or {}, sort_keys=True)
        post_target = html.escape(post_url)
        return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{escaped_title}</title>
  <style>
    body {{ font-family: sans-serif; margin: 2rem auto; max-width: 48rem; padding: 0 1rem; }}
    pre {{ white-space: pre-wrap; background: #f5f5f5; padding: 1rem; border-radius: 0.5rem; }}
    button {{ font-size: 1rem; padding: 0.8rem 1.2rem; cursor: pointer; }}
    #status {{ margin-top: 1rem; }}
  </style>
</head>
<body>
  <h1>{escaped_title}</h1>
  <p>{escaped_intro}</p>
  <pre>{pretty_context}</pre>
  <button id="ceremony">{html.escape(button_label)}</button>
  <p id="status"></p>
  <script>
    const publicKeyOptions = {options_json};
    const ceremony = {json.dumps(ceremony)};
    const postUrl = {json.dumps(post_target)};
    const statusEl = document.getElementById("status");
    const buttonEl = document.getElementById("ceremony");

    function b64urlToBytes(value) {{
      const padded = value.replace(/-/g, "+").replace(/_/g, "/")
        + "=".repeat((4 - value.length % 4) % 4);
      const binary = atob(padded);
      return Uint8Array.from(binary, (ch) => ch.charCodeAt(0));
    }}

    function bytesToB64url(value) {{
      const bytes = value instanceof Uint8Array ? value : new Uint8Array(value);
      let binary = "";
      for (const item of bytes) {{
        binary += String.fromCharCode(item);
      }}
      return btoa(binary).replace(/\\+/g, "-").replace(/\\//g, "_").replace(/=+$/g, "");
    }}

    function normalizePublicKey(options) {{
      const normalized = {{ ...options }};
      if (normalized.challenge) {{
        normalized.challenge = b64urlToBytes(normalized.challenge);
      }}
      if (normalized.user && normalized.user.id) {{
        normalized.user = {{ ...normalized.user, id: b64urlToBytes(normalized.user.id) }};
      }}
      if (Array.isArray(normalized.allowCredentials)) {{
        normalized.allowCredentials = normalized.allowCredentials.map((item) => ({{
          ...item,
          id: b64urlToBytes(item.id),
        }}));
      }}
      if (Array.isArray(normalized.excludeCredentials)) {{
        normalized.excludeCredentials = normalized.excludeCredentials.map((item) => ({{
          ...item,
          id: b64urlToBytes(item.id),
        }}));
      }}
      return normalized;
    }}

    function serializeCredential(credential) {{
      const response = credential.response;
      const payload = {{
        id: credential.id,
        rawId: bytesToB64url(credential.rawId),
        type: credential.type,
        response: {{}},
      }};
      if (response.clientDataJSON) {{
        payload.response.clientDataJSON = bytesToB64url(response.clientDataJSON);
      }}
      if (response.attestationObject) {{
        payload.response.attestationObject = bytesToB64url(response.attestationObject);
      }}
      if (response.authenticatorData) {{
        payload.response.authenticatorData = bytesToB64url(response.authenticatorData);
      }}
      if (response.signature) {{
        payload.response.signature = bytesToB64url(response.signature);
      }}
      if (response.userHandle) {{
        payload.response.userHandle = bytesToB64url(response.userHandle);
      }}
      if (typeof response.getTransports === "function") {{
        payload.transports = response.getTransports();
      }}
      return payload;
    }}

    async function runCeremony() {{
      statusEl.textContent = "Waiting for authenticator...";
      buttonEl.disabled = true;
      try {{
        const publicKey = normalizePublicKey(publicKeyOptions);
        const credential = ceremony === "register"
          ? await navigator.credentials.create({{ publicKey }})
          : await navigator.credentials.get({{ publicKey }});
        const response = await fetch(postUrl, {{
          method: "POST",
          headers: {{ "Content-Type": "application/json" }},
          body: JSON.stringify(serializeCredential(credential)),
        }});
        const payload = await response.json();
        if (!response.ok) {{
          throw new Error(payload.reason || payload.message || "ceremony_failed");
        }}
        statusEl.textContent = ceremony === "register"
          ? "Passkey registered successfully."
          : "Approval completed successfully.";
      }} catch (error) {{
        statusEl.textContent = `Ceremony failed: ${{error.message || error}}`;
      }} finally {{
        buttonEl.disabled = false;
      }}
    }}

    buttonEl.addEventListener("click", () => {{
      void runCeremony();
    }});
  </script>
</body>
</html>"""
