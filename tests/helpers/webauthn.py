"""Helpers for generating fake-but-valid WebAuthn browser payloads in tests."""

from __future__ import annotations

import base64
import hashlib
import secrets
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fido2.cose import ES256
from fido2.webauthn import (
    AttestationObject,
    AttestedCredentialData,
    AuthenticatorData,
    CollectedClientData,
)


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64url_decode(value: str | bytes) -> bytes:
    if isinstance(value, bytes):
        return value
    padded = value + "=" * ((4 - len(value) % 4) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


@dataclass(slots=True)
class WebAuthnTestCredential:
    rp_id: str
    origin: str
    credential_id: bytes = field(default_factory=lambda: secrets.token_bytes(32))
    private_key: ec.EllipticCurvePrivateKey = field(
        default_factory=lambda: ec.generate_private_key(ec.SECP256R1())
    )
    sign_count: int = 0
    transports: list[str] = field(default_factory=lambda: ["hybrid"])

    @property
    def credential_id_b64(self) -> str:
        return _b64url_encode(self.credential_id)

    def registration_payload(self, *, public_key_options: Mapping[str, Any]) -> dict[str, Any]:
        challenge = _b64url_decode(str(public_key_options["challenge"]))
        attested = AttestedCredentialData.create(
            b"\x00" * 16,
            self.credential_id,
            ES256.from_cryptography_key(self.private_key.public_key()),
        )
        auth_data = AuthenticatorData.create(
            hashlib.sha256(self.rp_id.encode("utf-8")).digest(),
            AuthenticatorData.FLAG.UP | AuthenticatorData.FLAG.AT,
            self.sign_count,
            credential_data=bytes(attested),
        )
        client_data = CollectedClientData.create(
            type="webauthn.create",
            challenge=challenge,
            origin=self.origin,
        )
        attestation = AttestationObject.create("none", auth_data, {})
        return {
            "id": self.credential_id_b64,
            "rawId": self.credential_id_b64,
            "type": "public-key",
            "response": {
                "clientDataJSON": _b64url_encode(bytes(client_data)),
                "attestationObject": _b64url_encode(bytes(attestation)),
            },
            "transports": list(self.transports),
        }

    def authentication_payload(
        self,
        *,
        public_key_options: Mapping[str, Any],
        challenge_b64url: str | None = None,
        sign_count: int | None = None,
        user_verified: bool = False,
    ) -> dict[str, Any]:
        challenge = _b64url_decode(
            challenge_b64url
            if challenge_b64url is not None
            else str(public_key_options["challenge"])
        )
        next_sign_count = self.sign_count + 1 if sign_count is None else int(sign_count)
        flags = AuthenticatorData.FLAG.UP
        if user_verified:
            flags |= AuthenticatorData.FLAG.UV
        auth_data = AuthenticatorData.create(
            hashlib.sha256(self.rp_id.encode("utf-8")).digest(),
            flags,
            next_sign_count,
        )
        client_data = CollectedClientData.create(
            type="webauthn.get",
            challenge=challenge,
            origin=self.origin,
        )
        signature = self.private_key.sign(
            bytes(auth_data) + client_data.hash,
            ec.ECDSA(hashes.SHA256()),
        )
        self.sign_count = next_sign_count
        return {
            "id": self.credential_id_b64,
            "rawId": self.credential_id_b64,
            "type": "public-key",
            "response": {
                "clientDataJSON": _b64url_encode(bytes(client_data)),
                "authenticatorData": _b64url_encode(bytes(auth_data)),
                "signature": _b64url_encode(signature),
            },
        }


def make_registration_payload(
    *,
    public_key_options: Mapping[str, Any],
    origin: str,
    rp_id: str | None = None,
    credential: WebAuthnTestCredential | None = None,
    transports: Iterable[str] | None = None,
) -> tuple[WebAuthnTestCredential, dict[str, Any]]:
    target = credential or WebAuthnTestCredential(
        rp_id=rp_id or str(public_key_options.get("rp", {}).get("id", "")),
        origin=origin,
    )
    if transports is not None:
        target.transports = [str(item) for item in transports if str(item).strip()]
    return target, target.registration_payload(public_key_options=public_key_options)


def make_authentication_payload(
    *,
    public_key_options: Mapping[str, Any],
    credential: WebAuthnTestCredential,
    challenge_b64url: str | None = None,
    sign_count: int | None = None,
    user_verified: bool = False,
) -> dict[str, Any]:
    return credential.authentication_payload(
        public_key_options=public_key_options,
        challenge_b64url=challenge_b64url,
        sign_count=sign_count,
        user_verified=user_verified,
    )
