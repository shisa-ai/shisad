"""Skill manifest schema, parsing, and dependency metadata validation."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, ValidationError, field_validator, model_validator

_SEMVER_RE = re.compile(
    r"^(?P<major>0|[1-9]\d*)\.(?P<minor>0|[1-9]\d*)\.(?P<patch>0|[1-9]\d*)"
    r"(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$"
)
_PINNED_VERSION_RE = re.compile(
    r"^==(?P<major>0|[1-9]\d*)\.(?P<minor>0|[1-9]\d*)\.(?P<patch>0|[1-9]\d*)"
    r"(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$"
)
_SUPPORTED_MANIFEST_MAJOR = 1
_REQUIRED_CAPABILITY_SECTIONS = ("network", "filesystem", "shell", "environment")


class SkillManifestError(ValueError):
    """Manifest validation error."""


def _parse_semver_parts(value: str) -> tuple[int, int, int]:
    match = _SEMVER_RE.fullmatch(value.strip())
    if match is None:
        raise SkillManifestError(f"Invalid semantic version '{value}'")
    return (
        int(match.group("major")),
        int(match.group("minor")),
        int(match.group("patch")),
    )


class NetworkCapability(BaseModel):
    domain: str
    reason: str = ""


class FilesystemCapability(BaseModel):
    path: str
    access: str = "read-only"
    reason: str = ""

    @field_validator("access")
    @classmethod
    def _validate_access(cls, value: str) -> str:
        normalized = value.strip().lower()
        if normalized not in {"read-only", "read-write"}:
            raise ValueError("filesystem access must be 'read-only' or 'read-write'")
        return normalized


class ShellCapability(BaseModel):
    command: str
    reason: str = ""


class EnvironmentCapability(BaseModel):
    var: str
    reason: str = ""


class SkillCapabilities(BaseModel):
    network: list[NetworkCapability] = Field(default_factory=list)
    filesystem: list[FilesystemCapability] = Field(default_factory=list)
    shell: list[ShellCapability] = Field(default_factory=list)
    environment: list[EnvironmentCapability] = Field(default_factory=list)


class SkillDependency(BaseModel):
    name: str
    version: str
    source: str
    digest: str
    signature: str

    @field_validator("version")
    @classmethod
    def _validate_version_pin(cls, value: str) -> str:
        if _PINNED_VERSION_RE.fullmatch(value.strip()) is None:
            raise ValueError("dependency version must be pinned (e.g., ==2.3.1)")
        return value.strip()

    @field_validator("digest")
    @classmethod
    def _validate_digest(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized.startswith("sha256:") or len(normalized) <= 7:
            raise ValueError("dependency digest must use sha256:<hex>")
        return normalized

    @field_validator("signature")
    @classmethod
    def _validate_signature(cls, value: str) -> str:
        normalized = value.strip()
        if ":" not in normalized:
            raise ValueError("dependency signature must be prefixed (e.g., ed25519:...)")
        return normalized


class SkillManifest(BaseModel):
    """Canonical skill manifest."""

    manifest_version: str = "1.0.0"
    name: str
    version: str
    author: str
    signature: str
    source_repo: str
    description: str = ""
    capabilities: SkillCapabilities
    dependencies: list[SkillDependency] = Field(default_factory=list)

    @field_validator("version", "manifest_version")
    @classmethod
    def _validate_semver(cls, value: str) -> str:
        _parse_semver_parts(value)
        return value

    @model_validator(mode="after")
    def _validate_manifest_compatibility(self) -> SkillManifest:
        major, _, _ = _parse_semver_parts(self.manifest_version)
        if major != _SUPPORTED_MANIFEST_MAJOR:
            raise ValueError(
                "Unsupported manifest major version "
                f"{major} (supported: {_SUPPORTED_MANIFEST_MAJOR})"
            )
        return self

    def canonical_payload(self) -> dict[str, Any]:
        payload = self.model_dump(mode="json")
        payload.pop("signature", None)
        return payload

    def manifest_hash(self) -> str:
        canonical = json.dumps(self.canonical_payload(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def verify_embedded_hash_signature(self) -> bool:
        signature = self.signature.strip()
        if not signature.startswith("sha256:"):
            return False
        return signature.split(":", 1)[1] == self.manifest_hash()


def breaking_surface_changed(previous: SkillManifest, current: SkillManifest) -> bool:
    """Return True when security-relevant manifest surface changed."""

    return (
        previous.capabilities.model_dump(mode="json")
        != current.capabilities.model_dump(mode="json")
        or [item.model_dump(mode="json") for item in previous.dependencies]
        != [item.model_dump(mode="json") for item in current.dependencies]
        or previous.source_repo != current.source_repo
        or previous.author != current.author
    )


def requires_major_bump(previous: SkillManifest, current: SkillManifest) -> bool:
    """Return True when a breaking surface change did not bump major version."""

    prev_major, _, _ = _parse_semver_parts(previous.version)
    current_major, _, _ = _parse_semver_parts(current.version)
    return breaking_surface_changed(previous, current) and current_major <= prev_major


def validate_dependency_metadata(
    manifest: SkillManifest,
    *,
    allowed_sources: set[str] | None = None,
) -> list[str]:
    """Validate dependency metadata against allowlist and pinning constraints."""

    errors: list[str] = []
    allowlist = {item.strip() for item in (allowed_sources or set()) if item.strip()}
    for dep in manifest.dependencies:
        if allowlist and dep.source not in allowlist:
            errors.append(f"dependency source not allowlisted: {dep.name}@{dep.source}")
        if _PINNED_VERSION_RE.fullmatch(dep.version) is None:
            errors.append(f"dependency version not pinned: {dep.name}@{dep.version}")
        if not dep.digest.startswith("sha256:"):
            errors.append(f"dependency digest invalid: {dep.name}")
        if ":" not in dep.signature:
            errors.append(f"dependency signature invalid: {dep.name}")
    return errors


def parse_manifest(
    manifest_path: Path,
    *,
    previous_manifest: SkillManifest | None = None,
    allowed_dependency_sources: set[str] | None = None,
) -> SkillManifest:
    """Parse and strictly validate a skill manifest from YAML."""

    try:
        raw = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise SkillManifestError(f"Manifest not found: {manifest_path}") from exc
    except yaml.YAMLError as exc:
        raise SkillManifestError(f"Invalid manifest YAML: {exc}") from exc

    if not isinstance(raw, dict):
        raise SkillManifestError("Manifest must be a YAML mapping")

    capabilities_raw = raw.get("capabilities")
    if not isinstance(capabilities_raw, dict):
        raise SkillManifestError("Manifest must declare capabilities mapping")
    missing_sections = [
        section for section in _REQUIRED_CAPABILITY_SECTIONS if section not in capabilities_raw
    ]
    if missing_sections:
        raise SkillManifestError(
            "Manifest must explicitly declare capability sections: "
            + ", ".join(sorted(missing_sections))
        )

    try:
        manifest = SkillManifest.model_validate(raw)
    except ValidationError as exc:
        raise SkillManifestError(f"Manifest validation failed: {exc}") from exc

    if previous_manifest is not None and requires_major_bump(previous_manifest, manifest):
        raise SkillManifestError(
            "Breaking manifest surface change requires major version bump"
        )

    dependency_errors = validate_dependency_metadata(
        manifest,
        allowed_sources=allowed_dependency_sources,
    )
    if dependency_errors:
        raise SkillManifestError("; ".join(dependency_errors))

    return manifest
