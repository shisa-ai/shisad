"""Minimal local signer stub for L2 live verification and manual smoke tests."""

from __future__ import annotations

import argparse
import base64
import json
import os
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from shisad.core.approval import canonical_json_dumps
from shisad.core.evidence import KmsArtifactBlobCodec


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8788)
    parser.add_argument("--public-key-out", type=Path, required=True)
    parser.add_argument(
        "--review-surface",
        default="provider_ui",
        choices=["provider_ui", "trusted_device_display", "opaque_device"],
    )
    parser.add_argument("--blind-sign", action="store_true")
    return parser


def _sign(private_key: Ed25519PrivateKey, envelope: dict[str, Any]) -> str:
    signature = private_key.sign(canonical_json_dumps(envelope).encode("utf-8"))
    return "base64:" + base64.b64encode(signature).decode("ascii")


def main() -> int:
    args = _build_parser().parse_args()
    private_key = Ed25519PrivateKey.generate()
    artifact_key = os.urandom(32)
    public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    args.public_key_out.parent.mkdir(parents=True, exist_ok=True)
    args.public_key_out.write_bytes(public_key_pem)

    class _Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0") or 0)
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
            if self.path == "/artifacts":
                response = _artifact_response(artifact_key=artifact_key, payload=payload)
            else:
                intent_envelope = dict(payload.get("intent_envelope", {}))
                response = {
                    "status": "approved",
                    "signer_key_id": str(payload.get("signer_key_id", "")),
                    "signature": _sign(private_key, intent_envelope),
                    "signed_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                    "review_surface": args.review_surface,
                    "blind_sign_detected": bool(args.blind_sign),
                }
            encoded = json.dumps(response).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def log_message(self, format: str, *args: object) -> None:
            return

    server = ThreadingHTTPServer((args.host, args.port), _Handler)
    print(
        json.dumps(
            {
                "url": f"http://{args.host}:{args.port}/sign",
                "artifact_url": f"http://{args.host}:{args.port}/artifacts",
                "public_key_path": str(args.public_key_out),
            }
        ),
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        return 0
    finally:
        server.server_close()
    return 0


def _artifact_response(*, artifact_key: bytes, payload: dict[str, Any]) -> dict[str, Any]:
    if payload.get("schema_version") != KmsArtifactBlobCodec.request_schema_version():
        return {"status": "error", "reason": "artifact_kms_invalid_request"}
    operation = str(payload.get("operation", "")).strip().lower()
    payload_b64 = str(payload.get("payload_b64", "")).strip()
    if not payload_b64:
        return {"status": "error", "reason": "artifact_kms_invalid_request"}
    try:
        request_bytes = base64.b64decode(payload_b64.encode("ascii"), validate=True)
    except Exception:
        return {"status": "error", "reason": "artifact_kms_invalid_request"}
    if operation == "encrypt":
        nonce = os.urandom(12)
        ciphertext = AESGCM(artifact_key).encrypt(
            nonce,
            request_bytes,
            b"shisad.artifact_crypt.v1:evidence",
        )
        envelope = {
            "v": 1,
            "nonce_b64": base64.b64encode(nonce).decode("ascii"),
            "ciphertext_b64": base64.b64encode(ciphertext).decode("ascii"),
        }
        encoded = json.dumps(envelope, separators=(",", ":")).encode("utf-8")
        return {
            "status": "ok",
            "payload_b64": base64.b64encode(encoded).decode("ascii"),
        }
    if operation != "decrypt":
        return {"status": "error", "reason": "artifact_kms_invalid_request"}
    try:
        envelope = json.loads(request_bytes.decode("utf-8"))
        nonce = base64.b64decode(str(envelope["nonce_b64"]).encode("ascii"), validate=True)
        ciphertext = base64.b64decode(
            str(envelope["ciphertext_b64"]).encode("ascii"),
            validate=True,
        )
        plaintext = AESGCM(artifact_key).decrypt(
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


if __name__ == "__main__":
    raise SystemExit(main())
