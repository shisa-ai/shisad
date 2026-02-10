"""Skill signature verification and key management."""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from enum import StrEnum

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from shisad.skills.manifest import SkillDependency, SkillManifest


class SignatureStatus(StrEnum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"
    UNSIGNED = "unsigned"
    INVALID = "invalid"


@dataclass(slots=True)
class VerificationResult:
    status: SignatureStatus
    key_id: str = ""
    reason: str = ""
    require_confirmation: bool = False
    blocked: bool = False


@dataclass(slots=True)
class SigningKey:
    key_id: str
    public_key: Ed25519PublicKey
    trust: str = "unknown"
    revoked: bool = False


class KeyRing:
    """In-memory key registry with rotation and revocation support."""

    def __init__(self) -> None:
        self._keys: dict[str, SigningKey] = {}

    def register_key(self, key: SigningKey) -> None:
        self._keys[key.key_id] = key

    def revoke_key(self, key_id: str) -> None:
        key = self._keys.get(key_id)
        if key is None:
            return
        key.revoked = True

    def rotate_key(self, *, old_key_id: str, new_key: SigningKey) -> None:
        self.revoke_key(old_key_id)
        self.register_key(new_key)

    def get(self, key_id: str) -> SigningKey | None:
        return self._keys.get(key_id)

    def trusted_keys(self) -> dict[str, SigningKey]:
        return {
            key_id: key
            for key_id, key in self._keys.items()
            if key.trust in {"org", "registry"}
        }


def generate_signing_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    private = Ed25519PrivateKey.generate()
    return private, private.public_key()


def encode_public_key(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes_raw()
    return base64.b64encode(raw).decode("ascii")


def decode_public_key(encoded: str) -> Ed25519PublicKey:
    raw = base64.b64decode(encoded.encode("ascii"), validate=True)
    return Ed25519PublicKey.from_public_bytes(raw)


def sign_manifest_payload(
    *,
    private_key: Ed25519PrivateKey,
    key_id: str,
    manifest: SkillManifest,
    file_hashes: dict[str, str],
) -> str:
    payload = canonical_signature_payload(manifest=manifest, file_hashes=file_hashes)
    signature = private_key.sign(payload)
    encoded = base64.b64encode(signature).decode("ascii")
    return f"ed25519:{key_id}:{encoded}"


def verify_manifest_signature(
    *,
    manifest: SkillManifest,
    file_hashes: dict[str, str],
    keyring: KeyRing,
) -> VerificationResult:
    signature = manifest.signature.strip()
    if not signature:
        return VerificationResult(
            status=SignatureStatus.UNSIGNED,
            reason="skill is unsigned",
            require_confirmation=True,
        )
    if not signature.startswith("ed25519:"):
        if manifest.verify_embedded_hash_signature():
            return VerificationResult(
                status=SignatureStatus.UNTRUSTED,
                reason="hash-only signature is not trust-anchored",
                require_confirmation=True,
            )
        return VerificationResult(
            status=SignatureStatus.INVALID,
            reason="unsupported signature format",
            blocked=True,
        )

    try:
        _, key_id, encoded = signature.split(":", 2)
        signature_bytes = base64.b64decode(encoded.encode("ascii"), validate=True)
    except Exception:
        return VerificationResult(
            status=SignatureStatus.INVALID,
            reason="malformed ed25519 signature",
            blocked=True,
        )

    key = keyring.get(key_id)
    if key is None:
        return VerificationResult(
            status=SignatureStatus.UNTRUSTED,
            key_id=key_id,
            reason="signed by unknown key",
            require_confirmation=True,
        )
    if key.revoked:
        return VerificationResult(
            status=SignatureStatus.INVALID,
            key_id=key_id,
            reason="signing key is revoked",
            blocked=True,
        )

    payload = canonical_signature_payload(manifest=manifest, file_hashes=file_hashes)
    try:
        key.public_key.verify(signature_bytes, payload)
    except Exception:
        return VerificationResult(
            status=SignatureStatus.INVALID,
            key_id=key_id,
            reason="signature verification failed",
            blocked=True,
        )

    if key.trust in {"org", "registry"}:
        return VerificationResult(
            status=SignatureStatus.TRUSTED,
            key_id=key_id,
            reason="signature verified",
        )
    return VerificationResult(
        status=SignatureStatus.UNTRUSTED,
        key_id=key_id,
        reason="signature valid but key trust not established",
        require_confirmation=True,
    )


def canonical_signature_payload(
    *,
    manifest: SkillManifest,
    file_hashes: dict[str, str],
) -> bytes:
    payload = {
        "manifest_hash": manifest.manifest_hash(),
        "file_hashes": {name: file_hashes[name] for name in sorted(file_hashes)},
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return canonical.encode("utf-8")


def verify_dependency_chain(
    *,
    dependencies: list[SkillDependency],
    allowed_sources: set[str],
) -> tuple[bool, list[str]]:
    """Verify dependency provenance declarations for install."""

    errors: list[str] = []
    for dep in dependencies:
        if dep.source not in allowed_sources:
            errors.append(f"dependency source blocked: {dep.name}@{dep.source}")
        if not dep.version.startswith("=="):
            errors.append(f"dependency version not pinned: {dep.name}@{dep.version}")
        if not dep.digest.startswith("sha256:") or len(dep.digest) <= 7:
            errors.append(f"dependency digest invalid: {dep.name}")
        if dep.signature.count(":") < 1:
            errors.append(f"dependency signature invalid: {dep.name}")
        # Deterministic fingerprint used for audit chain references.
        fingerprint = hashlib.sha256(
            f"{dep.name}|{dep.version}|{dep.source}|{dep.digest}".encode()
        ).hexdigest()
        if not fingerprint:
            errors.append(f"dependency fingerprint failure: {dep.name}")
    return (not errors, errors)
