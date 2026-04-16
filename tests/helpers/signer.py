"""Helpers for L2+ signer tests."""

from __future__ import annotations

import base64
import json
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

from shisad.core.approval import (
    IntentEnvelope,
    _eip712_digest,
    _eth_personal_sign_digest,
    canonical_json_dumps,
)


def generate_ed25519_private_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def generate_secp256k1_private_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256K1())


def public_key_pem(
    private_key: Ed25519PrivateKey | ec.EllipticCurvePrivateKey,
) -> str:
    return (
        private_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
    )


def sign_intent_envelope(private_key: Ed25519PrivateKey, envelope: dict[str, Any]) -> str:
    signature = private_key.sign(canonical_json_dumps(envelope).encode("utf-8"))
    return "base64:" + base64.b64encode(signature).decode("ascii")


def sign_intent_envelope_eth_personal(
    private_key: ec.EllipticCurvePrivateKey,
    envelope: dict[str, Any],
) -> str:
    """Sign an intent envelope using Ethereum personal-sign (keccak256 prefix)."""
    message = canonical_json_dumps(envelope).encode("utf-8")
    digest = _eth_personal_sign_digest(message)
    signature = private_key.sign(digest, ec.ECDSA(Prehashed(hashes.SHA256())))
    return "base64:" + base64.b64encode(signature).decode("ascii")


def sign_intent_envelope_eip712(
    private_key: ec.EllipticCurvePrivateKey,
    envelope: dict[str, Any],
) -> str:
    """Sign an intent envelope using EIP-712 typed data (keccak256 struct hash)."""
    intent = IntentEnvelope.model_validate(envelope)
    digest = _eip712_digest(intent)
    signature = private_key.sign(digest, ec.ECDSA(Prehashed(hashes.SHA256())))
    return "base64:" + base64.b64encode(signature).decode("ascii")


def verify_intent_signature(
    *,
    public_key_pem_text: str,
    envelope: dict[str, Any],
    signature: str,
) -> None:
    prefix = "base64:"
    if not signature.startswith(prefix):
        raise ValueError("signature must use base64: prefix")
    public_key = serialization.load_pem_public_key(public_key_pem_text.encode("utf-8"))
    if not isinstance(public_key, Ed25519PublicKey):
        raise TypeError("expected an Ed25519 public key")
    public_key.verify(
        base64.b64decode(signature[len(prefix) :].encode("ascii")),
        canonical_json_dumps(envelope).encode("utf-8"),
    )


class StubSignerService:
    """Minimal local HTTP signer used by integration and behavioral coverage."""

    def __init__(
        self,
        *,
        private_key: Ed25519PrivateKey | ec.EllipticCurvePrivateKey,
        algorithm: str = "ed25519",
        status: str = "approved",
        review_surface: str = "provider_ui",
        blind_sign_detected: bool = False,
        tamper_intent: bool = False,
        signer_key_id_override: str = "",
        signed_at_override: str = "",
    ) -> None:
        self._private_key = private_key
        self._algorithm = algorithm
        self._status = status
        self._review_surface = review_surface
        self._blind_sign_detected = blind_sign_detected
        self._tamper_intent = tamper_intent
        self._signer_key_id_override = signer_key_id_override
        self._signed_at_override = signed_at_override
        self.requests: list[dict[str, Any]] = []

    @contextmanager
    def run(self) -> Iterator[str]:
        owner = self

        class _Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", "0") or 0)
                body = self.rfile.read(length)
                payload = json.loads(body.decode("utf-8"))
                owner.requests.append(payload)
                intent_envelope = dict(payload.get("intent_envelope", {}))
                signed_envelope = dict(intent_envelope)
                if owner._tamper_intent:
                    signed_envelope["nonce"] = "tampered-nonce"
                response: dict[str, Any] = {
                    "status": owner._status,
                    "signer_key_id": owner._signer_key_id_override
                    or str(payload.get("signer_key_id", "")),
                    "review_surface": owner._review_surface,
                    "blind_sign_detected": owner._blind_sign_detected,
                    "signed_at": owner._signed_at_override
                    or datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                }
                if owner._status == "approved":
                    if owner._algorithm == "eip712":
                        assert isinstance(owner._private_key, ec.EllipticCurvePrivateKey)
                        response["signature"] = sign_intent_envelope_eip712(
                            owner._private_key,
                            signed_envelope,
                        )
                    elif owner._algorithm == "eth_personal_sign":
                        assert isinstance(owner._private_key, ec.EllipticCurvePrivateKey)
                        response["signature"] = sign_intent_envelope_eth_personal(
                            owner._private_key,
                            signed_envelope,
                        )
                    else:
                        assert isinstance(owner._private_key, Ed25519PrivateKey)
                        response["signature"] = sign_intent_envelope(
                            owner._private_key,
                            signed_envelope,
                        )
                encoded = json.dumps(response).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)

            def log_message(self, _format: str, *_args: object) -> None:
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield f"http://127.0.0.1:{server.server_port}/sign"
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
