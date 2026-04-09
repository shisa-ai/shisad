"""Local stub artifact-KMS service for evidence encryption tests."""

from __future__ import annotations

import base64
import json
import os
import time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class StubArtifactKmsService:
    """Serve a minimal encrypt/decrypt contract over local HTTP."""

    def __init__(
        self,
        *,
        key_material: bytes | None = None,
        bearer_token: str = "",
        request_delay_seconds: float = 0.0,
    ) -> None:
        self._key_material = key_material or os.urandom(32)
        self._bearer_token = bearer_token.strip()
        self._request_delay_seconds = max(0.0, float(request_delay_seconds))
        self.requests: list[dict[str, Any]] = []

    @contextmanager
    def run(self) -> Any:
        owner = self

        class _Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                if owner._bearer_token:
                    expected = f"Bearer {owner._bearer_token}"
                    if self.headers.get("Authorization", "").strip() != expected:
                        self._write_json(
                            401,
                            {"status": "error", "reason": "artifact_kms_unauthorized"},
                        )
                        return
                length = int(self.headers.get("Content-Length", "0") or 0)
                payload = json.loads(self.rfile.read(length).decode("utf-8"))
                owner.requests.append(payload)
                if owner._request_delay_seconds > 0.0:
                    time.sleep(owner._request_delay_seconds)
                if payload.get("schema_version") != "shisad.artifact_crypt.v1":
                    self._write_json(
                        400,
                        {"status": "error", "reason": "artifact_kms_invalid_request"},
                    )
                    return
                operation = str(payload.get("operation", "")).strip().lower()
                payload_b64 = str(payload.get("payload_b64", "")).strip()
                if not payload_b64:
                    self._write_json(
                        400,
                        {"status": "error", "reason": "artifact_kms_invalid_request"},
                    )
                    return
                try:
                    request_bytes = base64.b64decode(payload_b64.encode("ascii"), validate=True)
                except Exception:
                    self._write_json(
                        400,
                        {"status": "error", "reason": "artifact_kms_invalid_request"},
                    )
                    return
                if operation == "encrypt":
                    response_bytes = owner._encrypt(request_bytes)
                    self._write_json(
                        200,
                        {
                            "status": "ok",
                            "payload_b64": base64.b64encode(response_bytes).decode("ascii"),
                        },
                    )
                    return
                if operation == "decrypt":
                    response = owner._decrypt(request_bytes)
                    self._write_json(200, response)
                    return
                self._write_json(
                    400,
                    {"status": "error", "reason": "artifact_kms_invalid_request"},
                )

            def _write_json(self, status_code: int, payload: dict[str, Any]) -> None:
                encoded = json.dumps(payload).encode("utf-8")
                self.send_response(status_code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)

            def log_message(self, format: str, *args: object) -> None:
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield f"http://127.0.0.1:{server.server_port}/artifacts"
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def _encrypt(self, payload: bytes) -> bytes:
        nonce = os.urandom(12)
        ciphertext = AESGCM(self._key_material).encrypt(
            nonce,
            payload,
            b"shisad.artifact_crypt.v1:evidence",
        )
        envelope = {
            "v": 1,
            "nonce_b64": base64.b64encode(nonce).decode("ascii"),
            "ciphertext_b64": base64.b64encode(ciphertext).decode("ascii"),
        }
        return json.dumps(envelope, separators=(",", ":")).encode("utf-8")

    def _decrypt(self, payload: bytes) -> dict[str, Any]:
        try:
            envelope = json.loads(payload.decode("utf-8"))
            nonce = base64.b64decode(str(envelope["nonce_b64"]).encode("ascii"), validate=True)
            ciphertext = base64.b64decode(
                str(envelope["ciphertext_b64"]).encode("ascii"),
                validate=True,
            )
            plaintext = AESGCM(self._key_material).decrypt(
                nonce,
                ciphertext,
                b"shisad.artifact_crypt.v1:evidence",
            )
        except (InvalidTag, KeyError, TypeError, ValueError, json.JSONDecodeError):
            return {"status": "error", "reason": "decrypt_failed"}
        return {
            "status": "ok",
            "payload_b64": base64.b64encode(plaintext).decode("ascii"),
        }
