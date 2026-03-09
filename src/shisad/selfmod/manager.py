"""Signed self-modification artifact lifecycle management."""

from __future__ import annotations

import json
import shutil
import subprocess
import uuid
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, ValidationError


class ArtifactFileRecord(BaseModel):
    path: str
    sha256: str
    size: int


class ArtifactManifest(BaseModel):
    schema_version: str
    type: Literal["skill_bundle", "behavior_pack"]
    name: str
    version: str
    created_at: str = ""
    files: list[ArtifactFileRecord] = Field(default_factory=list)
    declared_capabilities: dict[str, list[str]] = Field(default_factory=dict)
    provenance: dict[str, Any] = Field(default_factory=dict)


class BehaviorPackInstructions(BaseModel):
    tone: Literal["strict", "neutral", "friendly"] | None = None
    custom_persona_text: str = ""


class SelfModificationProposal(BaseModel):
    proposal_id: str
    artifact_type: str
    name: str
    version: str
    artifact_path: str
    valid: bool
    warnings: list[str] = Field(default_factory=list)
    capability_diff: dict[str, Any] = Field(default_factory=dict)
    signer: str = ""
    reason: str = ""


class SelfModificationApplyResult(BaseModel):
    applied: bool
    proposal_id: str = ""
    change_id: str = ""
    requires_confirmation: bool = False
    warnings: list[str] = Field(default_factory=list)
    capability_diff: dict[str, Any] = Field(default_factory=dict)
    active_version: str = ""
    tool_names: list[str] = Field(default_factory=list)
    reason: str = ""


class SelfModificationRollbackResult(BaseModel):
    rolled_back: bool
    change_id: str = ""
    artifact_type: str = ""
    name: str = ""
    restored_version: str = ""
    active_version: str = ""
    reason: str = ""


class _InventoryEntry(BaseModel):
    enabled: bool = False
    active_version: str = ""


class _Inventory(BaseModel):
    skills: dict[str, _InventoryEntry] = Field(default_factory=dict)
    behavior_packs: dict[str, _InventoryEntry] = Field(default_factory=dict)


class _ProposalRecord(SelfModificationProposal):
    manifest: ArtifactManifest


class _ChangeRecord(BaseModel):
    change_id: str
    proposal_id: str
    artifact_type: str
    name: str
    previous_active_version: str = ""
    previous_enabled: bool = False
    new_active_version: str
    applied_at: str


class _ArtifactInspection(BaseModel):
    manifest: ArtifactManifest
    valid: bool
    signer: str = ""
    reason: str = ""
    warnings: list[str] = Field(default_factory=list)
    capability_diff: dict[str, Any] = Field(default_factory=dict)
    instructions: BehaviorPackInstructions | None = None


class SelfModificationManager:
    """Deterministic proposal/apply/rollback manager for signed artifacts."""

    def __init__(
        self,
        *,
        root: Path,
        allowed_signers_path: Path,
        skill_manager: Any,
        planner: Any,
        default_persona_tone: str,
        default_persona_text: str,
    ) -> None:
        self._root = root
        self._allowed_signers_path = allowed_signers_path
        self._skill_manager = skill_manager
        self._planner = planner
        self._default_persona_tone = default_persona_tone
        self._default_persona_text = default_persona_text
        self._proposal_dir = self._root / "proposals"
        self._change_dir = self._root / "changes"
        self._artifact_root = self._root / "artifacts"
        self._inventory_path = self._root / "inventory.yaml"
        self._incident_path = self._root / "last_incident.json"
        self._proposal_dir.mkdir(parents=True, exist_ok=True)
        self._change_dir.mkdir(parents=True, exist_ok=True)
        self._artifact_root.mkdir(parents=True, exist_ok=True)
        self._inventory = self._load_inventory()
        self._apply_behavior_overlay()

    def propose(self, artifact_path: Path) -> SelfModificationProposal:
        inspection = self._inspect_artifact(artifact_path)
        proposal = _ProposalRecord(
            proposal_id=uuid.uuid4().hex,
            artifact_type=inspection.manifest.type,
            name=inspection.manifest.name,
            version=inspection.manifest.version,
            artifact_path=str(artifact_path),
            valid=inspection.valid,
            warnings=list(inspection.warnings),
            capability_diff=dict(inspection.capability_diff),
            signer=inspection.signer,
            reason=inspection.reason,
            manifest=inspection.manifest,
        )
        self._proposal_path(proposal.proposal_id).write_text(
            proposal.model_dump_json(indent=2),
            encoding="utf-8",
        )
        return SelfModificationProposal.model_validate(proposal.model_dump(mode="json"))

    def apply(self, proposal_id: str, *, confirm: bool) -> SelfModificationApplyResult:
        proposal = self._load_proposal(proposal_id)
        if proposal is None:
            return SelfModificationApplyResult(
                applied=False,
                proposal_id=proposal_id,
                reason="proposal_not_found",
            )
        if not proposal.valid:
            return SelfModificationApplyResult(
                applied=False,
                proposal_id=proposal_id,
                warnings=list(proposal.warnings),
                capability_diff=dict(proposal.capability_diff),
                reason=proposal.reason or "proposal_invalid",
            )
        if not confirm:
            return SelfModificationApplyResult(
                applied=False,
                proposal_id=proposal_id,
                requires_confirmation=True,
                warnings=list(proposal.warnings),
                capability_diff=dict(proposal.capability_diff),
                active_version=self._active_version(
                    proposal.artifact_type,
                    proposal.name,
                ),
                reason="confirmation_required",
            )

        inspection = self._inspect_artifact(Path(proposal.artifact_path))
        if not inspection.valid:
            reason = inspection.reason or "integrity_mismatch"
            if reason.startswith("file_"):
                reason = "integrity_mismatch"
            self._record_incident(
                proposal_id=proposal.proposal_id,
                artifact_path=proposal.artifact_path,
                reason=reason,
            )
            return SelfModificationApplyResult(
                applied=False,
                proposal_id=proposal_id,
                warnings=list(proposal.warnings),
                capability_diff=dict(proposal.capability_diff),
                active_version=self._active_version(
                    proposal.artifact_type,
                    proposal.name,
                ),
                reason=reason,
            )

        entry = self._inventory_entry(proposal.artifact_type, proposal.name)
        previous_active = entry.active_version
        previous_enabled = entry.enabled
        stored_path = self._artifact_version_path(
            proposal.artifact_type,
            proposal.name,
            proposal.version,
        )
        if stored_path.exists():
            shutil.rmtree(stored_path)
        shutil.copytree(Path(proposal.artifact_path), stored_path)

        updated_entry = _InventoryEntry(enabled=True, active_version=proposal.version)
        self._set_inventory_entry(proposal.artifact_type, proposal.name, updated_entry)
        self._persist_inventory()

        tool_names: list[str] = []
        if proposal.artifact_type == "skill_bundle":
            installed = self._skill_manager.activate_bundle(stored_path / "payload")
            if installed is not None:
                tool_names = list(self._skill_manager.tool_names_for_skill(proposal.name))
        else:
            self._apply_behavior_overlay()

        change_id = uuid.uuid4().hex
        change = _ChangeRecord(
            change_id=change_id,
            proposal_id=proposal_id,
            artifact_type=proposal.artifact_type,
            name=proposal.name,
            previous_active_version=previous_active,
            previous_enabled=previous_enabled,
            new_active_version=proposal.version,
            applied_at=datetime.now(UTC).isoformat(),
        )
        self._change_path(change_id).write_text(
            change.model_dump_json(indent=2),
            encoding="utf-8",
        )
        return SelfModificationApplyResult(
            applied=True,
            proposal_id=proposal_id,
            change_id=change_id,
            warnings=list(proposal.warnings),
            capability_diff=dict(proposal.capability_diff),
            active_version=proposal.version,
            tool_names=tool_names,
            reason="ok",
        )

    def rollback(self, change_id: str) -> SelfModificationRollbackResult:
        change = self._load_change(change_id)
        if change is None:
            return SelfModificationRollbackResult(
                rolled_back=False,
                change_id=change_id,
                reason="change_not_found",
            )
        if change.previous_active_version:
            restored_entry = _InventoryEntry(
                enabled=change.previous_enabled or True,
                active_version=change.previous_active_version,
            )
            self._set_inventory_entry(change.artifact_type, change.name, restored_entry)
            self._persist_inventory()
            previous_path = self._artifact_version_path(
                change.artifact_type,
                change.name,
                change.previous_active_version,
            )
            if change.artifact_type == "skill_bundle":
                self._skill_manager.activate_bundle(previous_path / "payload")
            else:
                self._apply_behavior_overlay()
            restored_version = change.previous_active_version
            active_version = change.previous_active_version
        else:
            self._set_inventory_entry(
                change.artifact_type,
                change.name,
                _InventoryEntry(enabled=False, active_version=""),
            )
            self._persist_inventory()
            if change.artifact_type == "skill_bundle":
                self._skill_manager.revoke(skill_name=change.name, reason="rollback")
            else:
                self._apply_behavior_overlay()
            restored_version = ""
            active_version = ""
        return SelfModificationRollbackResult(
            rolled_back=True,
            change_id=change_id,
            artifact_type=change.artifact_type,
            name=change.name,
            restored_version=restored_version,
            active_version=active_version,
            reason="ok",
        )

    def status(self) -> dict[str, Any]:
        incident: dict[str, Any] = {}
        if self._incident_path.exists():
            try:
                incident = json.loads(self._incident_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                incident = {}
        return {
            "inventory_path": str(self._inventory_path),
            "skills": {
                name: entry.model_dump(mode="json")
                for name, entry in self._inventory.skills.items()
            },
            "behavior_packs": {
                name: entry.model_dump(mode="json")
                for name, entry in self._inventory.behavior_packs.items()
            },
            "incident": incident,
        }

    def _inspect_artifact(self, artifact_path: Path) -> _ArtifactInspection:
        manifest_path = artifact_path / "manifest.json"
        signature_path = artifact_path / "manifest.json.sig"
        if not manifest_path.exists():
            return _ArtifactInspection(
                manifest=_empty_manifest(),
                valid=False,
                reason="manifest_missing",
            )
        if not signature_path.exists():
            return _ArtifactInspection(
                manifest=_load_manifest(manifest_path),
                valid=False,
                reason="signature_missing",
            )
        manifest = _load_manifest(manifest_path)
        if manifest is None:
            return _ArtifactInspection(
                manifest=_empty_manifest(),
                valid=False,
                reason="invalid_manifest_schema",
            )
        verified, signer, signature_reason = _verify_signature(
            manifest_path=manifest_path,
            signature_path=signature_path,
            allowed_signers_path=self._allowed_signers_path,
        )
        if not verified:
            return _ArtifactInspection(
                manifest=manifest,
                valid=False,
                signer=signer,
                reason=signature_reason,
            )
        files_valid, files_reason = _validate_manifest_files(
            artifact_path=artifact_path,
            manifest=manifest,
        )
        if not files_valid:
            return _ArtifactInspection(
                manifest=manifest,
                valid=False,
                signer=signer,
                reason=files_reason,
            )
        if manifest.type == "skill_bundle":
            bundle_valid, bundle_reason, _instructions = _validate_skill_bundle(
                artifact_path=artifact_path,
                manifest=manifest,
            )
            if not bundle_valid:
                return _ArtifactInspection(
                    manifest=manifest,
                    valid=False,
                    signer=signer,
                    reason=bundle_reason,
                )
            warnings = _warnings_for_capability_diff(
                artifact_type=manifest.type,
                capability_diff=self._capability_diff(
                    manifest.type,
                    manifest.name,
                    manifest.declared_capabilities,
                ),
            )
            return _ArtifactInspection(
                manifest=manifest,
                valid=True,
                signer=signer,
                reason="ok",
                warnings=warnings,
                capability_diff=self._capability_diff(
                    manifest.type,
                    manifest.name,
                    manifest.declared_capabilities,
                ),
            )
        instructions = _validate_behavior_pack(
            artifact_path=artifact_path,
            manifest=manifest,
        )
        if instructions is None:
            return _ArtifactInspection(
                manifest=manifest,
                valid=False,
                signer=signer,
                reason="invalid_behavior_pack",
            )
        warnings = _warnings_for_capability_diff(
            artifact_type=manifest.type,
            capability_diff=self._capability_diff(
                manifest.type,
                manifest.name,
                manifest.declared_capabilities,
            ),
        )
        return _ArtifactInspection(
            manifest=manifest,
            valid=True,
            signer=signer,
            reason="ok",
            warnings=warnings,
            capability_diff=self._capability_diff(
                manifest.type,
                manifest.name,
                manifest.declared_capabilities,
            ),
            instructions=instructions,
        )

    def _apply_behavior_overlay(self) -> None:
        tone = self._default_persona_tone
        text_parts: list[str] = []
        for name in sorted(self._inventory.behavior_packs):
            entry = self._inventory.behavior_packs[name]
            if not entry.enabled or not entry.active_version:
                continue
            artifact_path = self._artifact_version_path(
                "behavior_pack",
                name,
                entry.active_version,
            )
            instructions = _load_behavior_pack_instructions(artifact_path / "instructions.yaml")
            if instructions is None:
                continue
            if instructions.tone:
                tone = instructions.tone
            if instructions.custom_persona_text.strip():
                text_parts.append(instructions.custom_persona_text.strip())
        custom_text = "\n\n".join(text_parts).strip() or self._default_persona_text
        setter = getattr(self._planner, "set_persona_defaults", None)
        if callable(setter):
            setter(tone=tone, custom_text=custom_text)

    def _capability_diff(
        self,
        artifact_type: str,
        name: str,
        new_capabilities: dict[str, list[str]],
    ) -> dict[str, Any]:
        previous = self._active_capabilities(artifact_type, name)
        keys = sorted(set(previous) | set(new_capabilities))
        added: dict[str, list[str]] = {}
        removed: dict[str, list[str]] = {}
        for key in keys:
            previous_values = list(previous.get(key, []))
            new_values = list(new_capabilities.get(key, []))
            added_values = [item for item in new_values if item not in previous_values]
            removed_values = [item for item in previous_values if item not in new_values]
            if added_values:
                added[key] = added_values
            if removed_values:
                removed[key] = removed_values
        return {"added": added, "removed": removed}

    def _active_capabilities(self, artifact_type: str, name: str) -> dict[str, list[str]]:
        active_version = self._active_version(artifact_type, name)
        if not active_version:
            return {}
        manifest_path = (
            self._artifact_version_path(artifact_type, name, active_version) / "manifest.json"
        )
        manifest = _load_manifest(manifest_path)
        if manifest is None:
            return {}
        return manifest.declared_capabilities

    def _active_version(self, artifact_type: str, name: str) -> str:
        entry = self._inventory_entry(artifact_type, name)
        return entry.active_version

    def _inventory_entry(self, artifact_type: str, name: str) -> _InventoryEntry:
        bucket = (
            self._inventory.skills
            if artifact_type == "skill_bundle"
            else self._inventory.behavior_packs
        )
        return bucket.get(name, _InventoryEntry())

    def _set_inventory_entry(self, artifact_type: str, name: str, entry: _InventoryEntry) -> None:
        bucket = (
            self._inventory.skills
            if artifact_type == "skill_bundle"
            else self._inventory.behavior_packs
        )
        bucket[name] = entry

    def _load_inventory(self) -> _Inventory:
        if not self._inventory_path.exists():
            return _Inventory()
        try:
            payload = yaml.safe_load(self._inventory_path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError):
            return _Inventory()
        if not isinstance(payload, dict):
            return _Inventory()
        try:
            return _Inventory.model_validate(payload)
        except ValidationError:
            return _Inventory()

    def _persist_inventory(self) -> None:
        self._inventory_path.parent.mkdir(parents=True, exist_ok=True)
        self._inventory_path.write_text(
            yaml.safe_dump(self._inventory.model_dump(mode="json"), sort_keys=False),
            encoding="utf-8",
        )

    def _proposal_path(self, proposal_id: str) -> Path:
        return self._proposal_dir / f"{proposal_id}.json"

    def _change_path(self, change_id: str) -> Path:
        return self._change_dir / f"{change_id}.json"

    def _load_proposal(self, proposal_id: str) -> _ProposalRecord | None:
        path = self._proposal_path(proposal_id)
        if not path.exists():
            return None
        try:
            return _ProposalRecord.model_validate_json(path.read_text(encoding="utf-8"))
        except (OSError, ValidationError):
            return None

    def _load_change(self, change_id: str) -> _ChangeRecord | None:
        path = self._change_path(change_id)
        if not path.exists():
            return None
        try:
            return _ChangeRecord.model_validate_json(path.read_text(encoding="utf-8"))
        except (OSError, ValidationError):
            return None

    def _artifact_version_path(self, artifact_type: str, name: str, version: str) -> Path:
        bucket = "skills" if artifact_type == "skill_bundle" else "behavior_packs"
        return self._artifact_root / bucket / name / version

    def _record_incident(self, *, proposal_id: str, artifact_path: str, reason: str) -> None:
        payload = {
            "proposal_id": proposal_id,
            "artifact_path": artifact_path,
            "reason": reason,
            "recorded_at": datetime.now(UTC).isoformat(),
        }
        self._incident_path.parent.mkdir(parents=True, exist_ok=True)
        self._incident_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _empty_manifest() -> ArtifactManifest:
    return ArtifactManifest(
        schema_version="1",
        type="skill_bundle",
        name="",
        version="",
    )


def _load_manifest(path: Path) -> ArtifactManifest | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    try:
        return ArtifactManifest.model_validate(payload)
    except ValidationError:
        return None


def _safe_relative_path(value: str) -> bool:
    try:
        path = PurePosixPath(value)
    except ValueError:
        return False
    return not path.is_absolute() and ".." not in path.parts


def _validate_manifest_files(
    *,
    artifact_path: Path,
    manifest: ArtifactManifest,
) -> tuple[bool, str]:
    declared = {item.path: item for item in manifest.files}
    if any(not _safe_relative_path(path) for path in declared):
        return False, "unsafe_relative_path"
    actual: dict[str, Path] = {}
    for path in sorted(artifact_path.rglob("*")):
        if not path.is_file():
            continue
        if path.name in {"manifest.json", "manifest.json.sig"}:
            continue
        relative = str(path.relative_to(artifact_path))
        if not _safe_relative_path(relative):
            return False, "unsafe_relative_path"
        actual[relative] = path
    if set(actual) != set(declared):
        return False, "file_set_mismatch"
    for relative, record in declared.items():
        data = actual[relative].read_bytes()
        import hashlib

        digest = hashlib.sha256(data).hexdigest()
        if digest != record.sha256:
            return False, "file_hash_mismatch"
        if len(data) != record.size:
            return False, "file_size_mismatch"
    return True, "ok"


def _validate_skill_bundle(
    *,
    artifact_path: Path,
    manifest: ArtifactManifest,
) -> tuple[bool, str, None]:
    try:
        from shisad.skills.manifest import parse_manifest
    except Exception:
        return False, "skill_manifest_loader_unavailable", None
    payload_root = artifact_path / "payload"
    manifest_path = payload_root / "skill.manifest.yaml"
    if not manifest_path.exists():
        return False, "skill_manifest_missing", None
    try:
        skill_manifest = parse_manifest(manifest_path)
    except Exception:
        return False, "invalid_skill_manifest", None
    declared = _skill_declared_capabilities(skill_manifest)
    if declared != manifest.declared_capabilities:
        return False, "declared_capabilities_mismatch", None
    return True, "ok", None


def _validate_behavior_pack(
    *,
    artifact_path: Path,
    manifest: ArtifactManifest,
) -> BehaviorPackInstructions | None:
    allowed = {"instructions.yaml"}
    for file_record in manifest.files:
        if file_record.path in allowed:
            continue
        if file_record.path.startswith("templates/"):
            continue
        return None
    return _load_behavior_pack_instructions(artifact_path / "instructions.yaml")


def _load_behavior_pack_instructions(path: Path) -> BehaviorPackInstructions | None:
    if not path.exists():
        return None
    try:
        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return None
    if not isinstance(payload, dict):
        return None
    try:
        return BehaviorPackInstructions.model_validate(payload)
    except ValidationError:
        return None


def _skill_declared_capabilities(skill_manifest: Any) -> dict[str, list[str]]:
    network = [item.domain for item in getattr(skill_manifest.capabilities, "network", [])]
    filesystem = [item.path for item in getattr(skill_manifest.capabilities, "filesystem", [])]
    shell = [item.command for item in getattr(skill_manifest.capabilities, "shell", [])]
    environment = [item.var for item in getattr(skill_manifest.capabilities, "environment", [])]
    tools = [
        f"skill.{skill_manifest.name}.{tool.name}"
        for tool in getattr(skill_manifest, "tools", [])
    ]
    return {
        "network": network,
        "filesystem": filesystem,
        "shell": shell,
        "environment": environment,
        "tools": tools,
    }


def _warnings_for_capability_diff(
    *,
    artifact_type: str,
    capability_diff: dict[str, Any],
) -> list[str]:
    warnings: list[str] = []
    added = dict(capability_diff.get("added", {}))
    if artifact_type == "behavior_pack":
        warnings.append("persona_overlay_change")
    if added.get("tools"):
        warnings.append("new_tool_surface")
    if added.get("network"):
        warnings.append("egress_surface_changed")
    if added.get("filesystem"):
        warnings.append("filesystem_surface_changed")
    return warnings


def _allowed_signer_principals(path: Path) -> list[str]:
    if not path.exists():
        return []
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
) -> tuple[bool, str, str]:
    principals = _allowed_signer_principals(allowed_signers_path)
    if not principals:
        return False, "", "trust_store_missing"
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
            return True, principal, "signature_verified"
    return False, "", "signature_verification_failed"
