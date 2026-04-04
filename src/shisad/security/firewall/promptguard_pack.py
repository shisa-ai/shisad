"""Signed PromptGuard model-pack helpers."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any, Literal

from pydantic import BaseModel, Field, ValidationError, field_validator

_PACK_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_PACK_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")
_LEGAL_FILENAMES = ("LICENSE", "NOTICE", "USE_POLICY.md", "README.md")


class PromptGuardModelPackFile(BaseModel):
    path: str
    sha256: str
    size: int


class PromptGuardModelPackManifest(BaseModel):
    schema_version: str = "1"
    type: Literal["promptguard_model_pack"] = "promptguard_model_pack"
    name: str
    version: str
    created_at: str
    files: list[PromptGuardModelPackFile] = Field(default_factory=list)
    provenance: dict[str, Any] = Field(default_factory=dict)
    runtime: dict[str, Any] = Field(default_factory=dict)

    @field_validator("name")
    @classmethod
    def _validate_name(cls, value: str) -> str:
        if not _PACK_NAME_RE.fullmatch(value):
            raise ValueError("invalid model-pack name")
        return value

    @field_validator("version")
    @classmethod
    def _validate_version(cls, value: str) -> str:
        if not _PACK_VERSION_RE.fullmatch(value):
            raise ValueError("invalid model-pack version")
        return value

    def digest(self) -> str:
        payload = json.dumps(
            self.model_dump(mode="json"),
            ensure_ascii=True,
            sort_keys=True,
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class PromptGuardModelPackInspection:
    valid: bool
    reason: str
    pack_dir: Path
    payload_dir: Path | None = None
    signer: str = ""
    manifest: PromptGuardModelPackManifest | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "reason": self.reason,
            "pack_dir": str(self.pack_dir),
            "payload_dir": str(self.payload_dir) if self.payload_dir is not None else "",
            "signer": self.signer,
            "manifest_digest": self.manifest.digest() if self.manifest is not None else "",
            "name": self.manifest.name if self.manifest is not None else "",
            "version": self.manifest.version if self.manifest is not None else "",
        }


def build_promptguard_model_pack(
    *,
    artifact_dir: Path,
    output_dir: Path,
    name: str,
    version: str,
    source_model_id: str,
    signing_key_path: Path,
    signer_principal: str,
    source_dir: Path | None = None,
    builder_id: str = "promptguard_artifacts.py",
    quantization: str = "fp32",
    created_at: str | None = None,
    force: bool = False,
) -> PromptGuardModelPackManifest:
    if not artifact_dir.is_dir():
        raise ValueError("artifact_dir_missing")
    if source_dir is not None and not source_dir.is_dir():
        raise ValueError("source_dir_missing")
    if not signing_key_path.is_file():
        raise ValueError("signing_key_missing")
    if not signer_principal.strip():
        raise ValueError("signer_principal_required")

    if output_dir.exists():
        if force:
            shutil.rmtree(output_dir)
        elif any(output_dir.iterdir()):
            raise ValueError("output_dir_exists")
    output_dir.mkdir(parents=True, exist_ok=True)

    payload_dir = output_dir / "payload"
    if payload_dir.exists():
        shutil.rmtree(payload_dir)
    shutil.copytree(artifact_dir, payload_dir)

    if source_dir is not None:
        for filename in _LEGAL_FILENAMES:
            source_path = source_dir / filename
            if source_path.is_file():
                shutil.copy2(source_path, output_dir / filename)

    manifest = PromptGuardModelPackManifest(
        name=name,
        version=version,
        created_at=_resolve_created_at(created_at),
        files=_collect_model_pack_files(output_dir),
        provenance={
            "source_model_id": source_model_id,
            "builder_id": builder_id,
            "signer_principal": signer_principal,
        },
        runtime={
            "format": "onnx",
            "execution_provider": "CPUExecutionProvider",
            "quantization": quantization,
        },
    )
    manifest_path = output_dir / "manifest.json"
    manifest_path.write_text(
        json.dumps(
            manifest.model_dump(mode="json"),
            indent=2,
            ensure_ascii=True,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    _sign_manifest(manifest_path=manifest_path, signing_key_path=signing_key_path)
    return manifest


def inspect_promptguard_model_pack(
    pack_dir: Path,
    *,
    allowed_signers_path: Path | None,
) -> PromptGuardModelPackInspection:
    manifest_path = pack_dir / "manifest.json"
    signature_path = pack_dir / "manifest.json.sig"
    if not manifest_path.is_file():
        return PromptGuardModelPackInspection(
            valid=False,
            reason="promptguard_pack_manifest_missing",
            pack_dir=pack_dir,
        )

    manifest = _load_manifest(manifest_path)
    if manifest is None:
        return PromptGuardModelPackInspection(
            valid=False,
            reason="promptguard_pack_invalid_manifest",
            pack_dir=pack_dir,
        )
    if not signature_path.is_file():
        return PromptGuardModelPackInspection(
            valid=False,
            reason="promptguard_pack_signature_missing",
            pack_dir=pack_dir,
            manifest=manifest,
        )
    if allowed_signers_path is None or not allowed_signers_path.is_file():
        return PromptGuardModelPackInspection(
            valid=False,
            reason="promptguard_pack_trust_store_missing",
            pack_dir=pack_dir,
            manifest=manifest,
        )
    verified, signer = _verify_signature(
        manifest_path=manifest_path,
        signature_path=signature_path,
        allowed_signers_path=allowed_signers_path,
    )
    if not verified:
        return PromptGuardModelPackInspection(
            valid=False,
            reason="promptguard_pack_signature_verification_failed",
            pack_dir=pack_dir,
            manifest=manifest,
        )

    files_valid, files_reason = _validate_manifest_files(pack_dir=pack_dir, manifest=manifest)
    if not files_valid:
        return PromptGuardModelPackInspection(
            valid=False,
            reason=files_reason,
            pack_dir=pack_dir,
            signer=signer,
            manifest=manifest,
        )
    payload_dir = pack_dir / "payload"
    if not payload_dir.is_dir():
        return PromptGuardModelPackInspection(
            valid=False,
            reason="promptguard_pack_payload_missing",
            pack_dir=pack_dir,
            signer=signer,
            manifest=manifest,
        )
    return PromptGuardModelPackInspection(
        valid=True,
        reason="ok",
        pack_dir=pack_dir,
        payload_dir=payload_dir,
        signer=signer,
        manifest=manifest,
    )


def _resolve_created_at(created_at: str | None) -> str:
    if created_at:
        return created_at
    source_date_epoch = os.environ.get("SOURCE_DATE_EPOCH", "").strip()
    if source_date_epoch:
        try:
            return datetime.fromtimestamp(int(source_date_epoch), UTC).isoformat()
        except ValueError:
            pass
    return datetime.now(UTC).isoformat()


def _collect_model_pack_files(root: Path) -> list[PromptGuardModelPackFile]:
    files: list[PromptGuardModelPackFile] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if path.name in {"manifest.json", "manifest.json.sig"}:
            continue
        relative = path.relative_to(root).as_posix()
        files.append(
            PromptGuardModelPackFile(
                path=relative,
                sha256=_hash_file(path),
                size=path.stat().st_size,
            )
        )
    return files


def _load_manifest(path: Path) -> PromptGuardModelPackManifest | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    try:
        return PromptGuardModelPackManifest.model_validate(payload)
    except ValidationError:
        return None


def _hash_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _safe_relative_path(value: str) -> bool:
    try:
        path = PurePosixPath(value)
    except ValueError:
        return False
    return not path.is_absolute() and ".." not in path.parts


def _validate_manifest_files(
    *,
    pack_dir: Path,
    manifest: PromptGuardModelPackManifest,
) -> tuple[bool, str]:
    declared = {item.path: item for item in manifest.files}
    if any(not _safe_relative_path(path) for path in declared):
        return False, "promptguard_pack_unsafe_relative_path"

    actual: dict[str, Path] = {}
    for path in sorted(pack_dir.rglob("*")):
        if not path.is_file():
            continue
        if path.name in {"manifest.json", "manifest.json.sig"}:
            continue
        relative = path.relative_to(pack_dir).as_posix()
        if not _safe_relative_path(relative):
            return False, "promptguard_pack_unsafe_relative_path"
        actual[relative] = path

    if set(actual) != set(declared):
        return False, "promptguard_pack_file_set_mismatch"

    for relative, record in declared.items():
        actual_path = actual[relative]
        data = actual_path.read_bytes()
        if hashlib.sha256(data).hexdigest() != record.sha256:
            return False, "promptguard_pack_file_hash_mismatch"
        if len(data) != record.size:
            return False, "promptguard_pack_file_size_mismatch"
    return True, "ok"


def _allowed_signer_principals(path: Path) -> list[str]:
    principals: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        principals.append(stripped.split()[0])
    return principals


def _verify_signature(
    *,
    manifest_path: Path,
    signature_path: Path,
    allowed_signers_path: Path,
) -> tuple[bool, str]:
    principals = _allowed_signer_principals(allowed_signers_path)
    if not principals:
        return False, ""
    manifest_text = manifest_path.read_text(encoding="utf-8")
    for principal in principals:
        result = subprocess.run(
            [
                "ssh-keygen",
                "-Y",
                "verify",
                "-f",
                str(allowed_signers_path),
                "-I",
                principal,
                "-n",
                "file",
                "-s",
                str(signature_path),
            ],
            input=manifest_text,
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            return True, principal
    return False, ""


def _sign_manifest(*, manifest_path: Path, signing_key_path: Path) -> None:
    subprocess.run(
        [
            "ssh-keygen",
            "-Y",
            "sign",
            "-f",
            str(signing_key_path),
            "-n",
            "file",
            str(manifest_path),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
