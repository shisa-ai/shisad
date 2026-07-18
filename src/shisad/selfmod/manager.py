"""Signed self-modification artifact lifecycle management."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import uuid
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, ValidationError, field_validator

_IDENTIFIER_RE = re.compile(r"^[a-f0-9]{32}$")
_ARTIFACT_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_ARTIFACT_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")


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

    @field_validator("name")
    @classmethod
    def _validate_name(cls, value: str) -> str:
        if not _ARTIFACT_NAME_RE.fullmatch(value):
            raise ValueError("invalid artifact name")
        return value

    @field_validator("version")
    @classmethod
    def _validate_version(cls, value: str) -> str:
        if not _ARTIFACT_VERSION_RE.fullmatch(value):
            raise ValueError("invalid artifact version")
        return value


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


class _SelfModificationOperationError(RuntimeError):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True, slots=True)
class _StagedArtifactCopy:
    target_path: Path
    backup_path: Path | None = None


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
        _write_text_atomic(
            self._proposal_path(proposal.proposal_id),
            proposal.model_dump_json(indent=2),
        )
        return SelfModificationProposal.model_validate(proposal.model_dump(mode="json"))

    def apply(self, proposal_id: str, *, confirm: bool) -> SelfModificationApplyResult:
        if not _is_valid_identifier(proposal_id):
            return SelfModificationApplyResult(
                applied=False,
                proposal_id=proposal_id,
                reason="invalid_proposal_id",
            )
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
            reason = _normalize_integrity_reason(inspection.reason)
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
        if inspection.manifest.model_dump(mode="json") != proposal.manifest.model_dump(mode="json"):
            self._record_incident(
                proposal_id=proposal.proposal_id,
                artifact_path=proposal.artifact_path,
                reason="proposal_artifact_changed",
            )
            return SelfModificationApplyResult(
                applied=False,
                proposal_id=proposal_id,
                warnings=list(inspection.warnings),
                capability_diff=dict(inspection.capability_diff),
                active_version=self._active_version(
                    proposal.artifact_type,
                    proposal.name,
                ),
                reason="proposal_artifact_changed",
            )

        previous_inventory = self._inventory.model_copy(deep=True)
        previous_entry = self._inventory_entry_from(
            previous_inventory,
            proposal.artifact_type,
            proposal.name,
        )
        candidate_inventory = previous_inventory.model_copy(deep=True)
        self._set_inventory_entry_in(
            candidate_inventory,
            proposal.artifact_type,
            proposal.name,
            _InventoryEntry(enabled=True, active_version=proposal.version),
        )
        try:
            staged_copy = self._stage_artifact_copy(
                artifact_type=proposal.artifact_type,
                name=proposal.name,
                version=proposal.version,
                source_path=Path(proposal.artifact_path),
            )
        except OSError:
            return SelfModificationApplyResult(
                applied=False,
                proposal_id=proposal_id,
                warnings=list(inspection.warnings),
                capability_diff=dict(inspection.capability_diff),
                active_version=self._active_version(
                    proposal.artifact_type,
                    proposal.name,
                ),
                reason="artifact_store_copy_failed",
            )

        try:
            tool_names = self._apply_runtime_for_inventory(
                candidate_inventory,
                proposal.artifact_type,
                proposal.name,
            )
            change_id = uuid.uuid4().hex
            change = _ChangeRecord(
                change_id=change_id,
                proposal_id=proposal_id,
                artifact_type=proposal.artifact_type,
                name=proposal.name,
                previous_active_version=previous_entry.active_version,
                previous_enabled=previous_entry.enabled,
                new_active_version=proposal.version,
                applied_at=datetime.now(UTC).isoformat(),
            )
            self._commit_inventory_and_change(candidate_inventory, change)
        except _SelfModificationOperationError as exc:
            try:
                self._restore_staged_artifact(staged_copy)
            except OSError:
                self._record_incident(
                    proposal_id=proposal.proposal_id,
                    artifact_path=str(staged_copy.target_path),
                    reason="artifact_store_restore_failed",
                )
                return SelfModificationApplyResult(
                    applied=False,
                    proposal_id=proposal_id,
                    warnings=list(inspection.warnings),
                    capability_diff=dict(inspection.capability_diff),
                    active_version=previous_entry.active_version if previous_entry.enabled else "",
                    reason="artifact_store_restore_failed",
                )
            self._restore_runtime(previous_inventory, proposal.artifact_type, proposal.name)
            return SelfModificationApplyResult(
                applied=False,
                proposal_id=proposal_id,
                warnings=list(inspection.warnings),
                capability_diff=dict(inspection.capability_diff),
                active_version=previous_entry.active_version if previous_entry.enabled else "",
                reason=exc.reason,
            )

        self._inventory = candidate_inventory
        self._finalize_staged_artifact(staged_copy)
        return SelfModificationApplyResult(
            applied=True,
            proposal_id=proposal_id,
            change_id=change_id,
            warnings=list(inspection.warnings),
            capability_diff=dict(inspection.capability_diff),
            active_version=proposal.version,
            tool_names=tool_names,
            reason="ok",
        )

    def rollback(self, change_id: str) -> SelfModificationRollbackResult:
        if not _is_valid_identifier(change_id):
            return SelfModificationRollbackResult(
                rolled_back=False,
                change_id=change_id,
                reason="invalid_change_id",
            )
        change = self._load_change(change_id)
        if change is None:
            return SelfModificationRollbackResult(
                rolled_back=False,
                change_id=change_id,
                reason="change_not_found",
            )
        current_inventory = self._inventory.model_copy(deep=True)
        candidate_inventory = current_inventory.model_copy(deep=True)
        if change.previous_active_version:
            if change.previous_enabled:
                previous_path = self._artifact_version_path(
                    change.artifact_type,
                    change.name,
                    change.previous_active_version,
                )
                inspection = self._inspect_artifact(previous_path)
                if not inspection.valid:
                    reason = _normalize_integrity_reason(inspection.reason)
                    self._record_incident(
                        proposal_id=change.proposal_id,
                        artifact_path=str(previous_path),
                        reason=reason,
                    )
                    return SelfModificationRollbackResult(
                        rolled_back=False,
                        change_id=change_id,
                        artifact_type=change.artifact_type,
                        name=change.name,
                        active_version=self._active_version(change.artifact_type, change.name),
                        reason=reason,
                    )
            restored_entry = _InventoryEntry(
                enabled=change.previous_enabled,
                active_version=change.previous_active_version,
            )
            self._set_inventory_entry_in(
                candidate_inventory,
                change.artifact_type,
                change.name,
                restored_entry,
            )
            restored_version = change.previous_active_version if change.previous_enabled else ""
        else:
            self._set_inventory_entry_in(
                candidate_inventory,
                change.artifact_type,
                change.name,
                _InventoryEntry(enabled=False, active_version=""),
            )
            restored_version = ""
        try:
            self._apply_runtime_for_inventory(
                candidate_inventory,
                change.artifact_type,
                change.name,
            )
            self._persist_inventory_snapshot(candidate_inventory)
        except OSError:
            self._restore_runtime(current_inventory, change.artifact_type, change.name)
            return SelfModificationRollbackResult(
                rolled_back=False,
                change_id=change_id,
                artifact_type=change.artifact_type,
                name=change.name,
                active_version=self._active_version(change.artifact_type, change.name),
                reason="inventory_persist_failed",
            )
        except _SelfModificationOperationError as exc:
            self._restore_runtime(current_inventory, change.artifact_type, change.name)
            return SelfModificationRollbackResult(
                rolled_back=False,
                change_id=change_id,
                artifact_type=change.artifact_type,
                name=change.name,
                active_version=self._active_version(change.artifact_type, change.name),
                reason=exc.reason,
            )
        self._inventory = candidate_inventory
        active_version = restored_version
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
        manifest = _load_manifest(manifest_path)
        if manifest is None:
            return _ArtifactInspection(
                manifest=_empty_manifest(),
                valid=False,
                reason="invalid_manifest_schema",
            )
        if not signature_path.exists():
            return _ArtifactInspection(
                manifest=manifest,
                valid=False,
                reason="signature_missing",
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
        self._apply_behavior_overlay_for_inventory(self._inventory)

    def _apply_behavior_overlay_for_inventory(self, inventory: _Inventory) -> None:
        tone = self._default_persona_tone
        text_parts: list[str] = []
        for name in sorted(inventory.behavior_packs):
            entry = inventory.behavior_packs[name]
            if not entry.enabled or not entry.active_version:
                continue
            try:
                artifact_path = self._artifact_version_path(
                    "behavior_pack",
                    name,
                    entry.active_version,
                )
            except ValueError:
                continue
            instructions = _load_behavior_pack_instructions(artifact_path / "instructions.yaml")
            if instructions is None:
                continue
            if instructions.tone:
                # Deterministic precedence: alphabetical-last enabled pack wins on tone.
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
        try:
            manifest_path = (
                self._artifact_version_path(artifact_type, name, active_version) / "manifest.json"
            )
        except ValueError:
            return {}
        manifest = _load_manifest(manifest_path)
        if manifest is None:
            return {}
        return manifest.declared_capabilities

    def _active_version(self, artifact_type: str, name: str) -> str:
        entry = self._inventory_entry(artifact_type, name)
        return entry.active_version

    def _inventory_entry(self, artifact_type: str, name: str) -> _InventoryEntry:
        return self._inventory_entry_from(self._inventory, artifact_type, name)

    @staticmethod
    def _inventory_entry_from(
        inventory: _Inventory,
        artifact_type: str,
        name: str,
    ) -> _InventoryEntry:
        bucket = inventory.skills if artifact_type == "skill_bundle" else inventory.behavior_packs
        return bucket.get(name, _InventoryEntry())

    def _set_inventory_entry(self, artifact_type: str, name: str, entry: _InventoryEntry) -> None:
        self._set_inventory_entry_in(self._inventory, artifact_type, name, entry)

    @staticmethod
    def _set_inventory_entry_in(
        inventory: _Inventory,
        artifact_type: str,
        name: str,
        entry: _InventoryEntry,
    ) -> None:
        bucket = inventory.skills if artifact_type == "skill_bundle" else inventory.behavior_packs
        bucket[name] = entry

    def _apply_runtime_for_inventory(
        self,
        inventory: _Inventory,
        artifact_type: str,
        name: str,
    ) -> list[str]:
        entry = self._inventory_entry_from(inventory, artifact_type, name)
        if artifact_type == "skill_bundle":
            try:
                if entry.enabled and entry.active_version:
                    payload_root = (
                        self._artifact_version_path(
                            artifact_type,
                            name,
                            entry.active_version,
                        )
                        / "payload"
                    )
                    installed = self._skill_manager.activate_bundle(payload_root)
                    if installed is None:
                        raise _SelfModificationOperationError("skill_activation_failed")
                    return list(self._skill_manager.tool_names_for_skill(name))
                self._skill_manager.revoke(skill_name=name, reason="selfmod_inventory_transition")
                return []
            except _SelfModificationOperationError:
                raise
            except Exception as exc:
                raise _SelfModificationOperationError("skill_activation_failed") from exc
        try:
            self._apply_behavior_overlay_for_inventory(inventory)
        except Exception as exc:
            raise _SelfModificationOperationError("behavior_overlay_failed") from exc
        return []

    def _restore_runtime(self, inventory: _Inventory, artifact_type: str, name: str) -> None:
        try:
            self._apply_runtime_for_inventory(inventory, artifact_type, name)
        except _SelfModificationOperationError:
            return None

    def _persist_inventory_snapshot(self, inventory: _Inventory) -> None:
        _write_text_atomic(
            self._inventory_path,
            yaml.safe_dump(inventory.model_dump(mode="json"), sort_keys=False),
        )

    def _commit_inventory_and_change(
        self,
        inventory: _Inventory,
        change: _ChangeRecord,
    ) -> None:
        try:
            self._persist_inventory_snapshot(inventory)
        except OSError as exc:
            raise _SelfModificationOperationError("inventory_persist_failed") from exc
        try:
            _write_text_atomic(
                self._change_path(change.change_id),
                change.model_dump_json(indent=2),
            )
        except OSError as exc:
            with suppress(OSError):
                self._persist_inventory_snapshot(self._inventory)
            raise _SelfModificationOperationError("change_record_persist_failed") from exc

    def _stage_artifact_copy(
        self,
        *,
        artifact_type: str,
        name: str,
        version: str,
        source_path: Path,
    ) -> _StagedArtifactCopy:
        target_path = self._artifact_version_path(artifact_type, name, version)
        target_path.parent.mkdir(parents=True, exist_ok=True)
        staging_path = target_path.parent / f".{target_path.name}.tmp-{uuid.uuid4().hex}"
        backup_path = target_path.parent / f".{target_path.name}.bak-{uuid.uuid4().hex}"
        staged_backup: Path | None = None
        try:
            shutil.copytree(source_path, staging_path)
            if target_path.exists():
                target_path.replace(backup_path)
                staged_backup = backup_path
            staging_path.replace(target_path)
            return _StagedArtifactCopy(target_path=target_path, backup_path=staged_backup)
        except OSError:
            if staging_path.exists():
                shutil.rmtree(staging_path, ignore_errors=True)
            if staged_backup is not None and staged_backup.exists() and not target_path.exists():
                backup_path.replace(target_path)
            raise

    @staticmethod
    def _restore_staged_artifact(staged_copy: _StagedArtifactCopy) -> None:
        if staged_copy.target_path.exists():
            shutil.rmtree(staged_copy.target_path, ignore_errors=True)
        if staged_copy.backup_path is not None and staged_copy.backup_path.exists():
            staged_copy.backup_path.replace(staged_copy.target_path)

    @staticmethod
    def _finalize_staged_artifact(staged_copy: _StagedArtifactCopy) -> None:
        if staged_copy.backup_path is not None and staged_copy.backup_path.exists():
            shutil.rmtree(staged_copy.backup_path, ignore_errors=True)

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
        self._persist_inventory_snapshot(self._inventory)

    def _proposal_path(self, proposal_id: str) -> Path:
        return self._proposal_dir / f"{proposal_id}.json"

    def _change_path(self, change_id: str) -> Path:
        return self._change_dir / f"{change_id}.json"

    def _load_proposal(self, proposal_id: str) -> _ProposalRecord | None:
        if not _is_valid_identifier(proposal_id):
            return None
        path = self._proposal_path(proposal_id)
        if not path.exists():
            return None
        try:
            return _ProposalRecord.model_validate_json(path.read_text(encoding="utf-8"))
        except (OSError, ValidationError):
            return None

    def _load_change(self, change_id: str) -> _ChangeRecord | None:
        if not _is_valid_identifier(change_id):
            return None
        path = self._change_path(change_id)
        if not path.exists():
            return None
        try:
            return _ChangeRecord.model_validate_json(path.read_text(encoding="utf-8"))
        except (OSError, ValidationError):
            return None

    def _artifact_version_path(self, artifact_type: str, name: str, version: str) -> Path:
        if not _ARTIFACT_NAME_RE.fullmatch(name) or not _ARTIFACT_VERSION_RE.fullmatch(version):
            raise ValueError("unsafe_artifact_identity")
        bucket = "skills" if artifact_type == "skill_bundle" else "behavior_packs"
        return self._artifact_root / bucket / name / version

    def _record_incident(self, *, proposal_id: str, artifact_path: str, reason: str) -> None:
        payload = {
            "proposal_id": proposal_id,
            "artifact_path": artifact_path,
            "reason": reason,
            "recorded_at": datetime.now(UTC).isoformat(),
        }
        _write_text_atomic(self._incident_path, json.dumps(payload, indent=2))


def _is_valid_identifier(value: str) -> bool:
    return _IDENTIFIER_RE.fullmatch(value.strip()) is not None


def _normalize_integrity_reason(reason: str) -> str:
    normalized = reason.strip() or "integrity_mismatch"
    if normalized.startswith("file_"):
        return "integrity_mismatch"
    return normalized


def _write_text_atomic(path: Path, content: str) -> None:
    tmp_path = path.parent / f".{path.name}.tmp-{uuid.uuid4().hex}"
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        tmp_path.write_text(content, encoding="utf-8")
        tmp_path.replace(path)
    except OSError:
        if tmp_path.exists():
            tmp_path.unlink(missing_ok=True)
        raise


def _empty_manifest() -> ArtifactManifest:
    return ArtifactManifest.model_construct(
        schema_version="1",
        type="skill_bundle",
        name="",
        version="",
        created_at="",
        files=[],
        declared_capabilities={},
        provenance={},
    )


def _load_manifest(path: Path) -> ArtifactManifest | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
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
        f"skill.{skill_manifest.name}.{tool.name}" for tool in getattr(skill_manifest, "tools", [])
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
