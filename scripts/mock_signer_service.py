"""Minimal local signer stub for L2 live verification and manual smoke tests."""

from __future__ import annotations

import argparse
import base64
import json
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from shisad.core.approval import canonical_json_dumps


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


if __name__ == "__main__":
    raise SystemExit(main())
