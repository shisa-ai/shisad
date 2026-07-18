"""Signed self-modification artifact lifecycle management."""

from __future__ import annotations

import hashlib
import json
import logging
import re
import shutil
import stat
import subprocess
import uuid
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any, Literal

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

from shisad.core.artifact_staging import (
    DEFAULT_ARTIFACT_STAGE_MAX_BYTES as _ARTIFACT_STAGE_MAX_BYTES,
)
from shisad.core.artifact_staging import (
    DEFAULT_ARTIFACT_STAGE_MAX_ENTRIES as _ARTIFACT_STAGE_MAX_ENTRIES,
)
from shisad.core.artifact_staging import (
    copy_bounded_regular_tree,
    fsync_directory,
)
from shisad.core.atomic_state import (
    AtomicWriteError,
    AtomicWriteFaultInjector,
    StateLoadResult,
    StateLoadStatus,
    StatePersistenceDegradedError,
    atomic_write_bytes,
    decode_json_document,
    decode_versioned_json_snapshot,
    encode_versioned_json_snapshot,
    ensure_owner_only_directory,
    read_owned_regular_file,
    remove_owner_controlled_directory_contents,
    validate_directory_ancestry,
)

_IDENTIFIER_RE = re.compile(r"^[a-f0-9]{32}$")
_ARTIFACT_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_ARTIFACT_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")
_SELFMOD_INVENTORY_VERSION = 1
_SELFMOD_INVENTORY_DOMAIN_MARKER = b"shisad-selfmod-inventory-domain-v1\n"

logger = logging.getLogger(__name__)


class ArtifactFileRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str
    sha256: str
    size: int


class ArtifactManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1"]
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
    model_config = ConfigDict(extra="forbid")

    enabled: bool = Field(default=False, strict=True)
    active_version: str = ""


class _Inventory(BaseModel):
    model_config = ConfigDict(extra="forbid")

    skills: dict[str, _InventoryEntry] = Field(default_factory=dict)
    behavior_packs: dict[str, _InventoryEntry] = Field(default_factory=dict)


class _ProposalRecord(SelfModificationProposal):
    model_config = ConfigDict(extra="forbid")

    artifact_type: Literal["skill_bundle", "behavior_pack"]
    valid: bool = Field(strict=True)
    manifest: ArtifactManifest | None = None

    @model_validator(mode="after")
    def _validate_record_semantics(self) -> _ProposalRecord:
        if not _is_valid_identifier(self.proposal_id):
            raise ValueError("invalid proposal id")
        if self.name and not _ARTIFACT_NAME_RE.fullmatch(self.name):
            raise ValueError("invalid proposal name")
        if self.version and not _ARTIFACT_VERSION_RE.fullmatch(self.version):
            raise ValueError("invalid proposal version")
        if self.valid:
            if self.manifest is None:
                raise ValueError("valid proposal is missing its manifest")
            if (
                not self.name
                or not self.version
                or self.artifact_type != self.manifest.type
                or self.name != self.manifest.name
                or self.version != self.manifest.version
            ):
                raise ValueError("proposal identity does not match manifest")
        return self


class _ChangeRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    change_id: str
    proposal_id: str
    artifact_type: Literal["skill_bundle", "behavior_pack"]
    name: str
    previous_active_version: str = ""
    previous_enabled: bool = Field(default=False, strict=True)
    new_active_version: str
    applied_at: str

    @model_validator(mode="after")
    def _validate_record_semantics(self) -> _ChangeRecord:
        if not _is_valid_identifier(self.change_id) or not _is_valid_identifier(self.proposal_id):
            raise ValueError("invalid change identity")
        if not _ARTIFACT_NAME_RE.fullmatch(self.name):
            raise ValueError("invalid change name")
        for version in (self.previous_active_version, self.new_active_version):
            if version and not _ARTIFACT_VERSION_RE.fullmatch(version):
                raise ValueError("invalid change version")
        if not self.new_active_version:
            raise ValueError("missing new active version")
        return self


class _IncidentRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    proposal_id: str
    artifact_path: str
    reason: str
    recorded_at: str


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
    staging_path: Path


@dataclass(frozen=True, slots=True)
class _PublishedArtifactCopy:
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
        self._root = Path(root)
        self._allowed_signers_path = allowed_signers_path
        self._skill_manager = skill_manager
        self._planner = planner
        self._default_persona_tone = default_persona_tone
        self._default_persona_text = default_persona_text
        self._proposal_dir = self._root / "proposals"
        self._change_dir = self._root / "changes"
        self._artifact_root = self._root / "artifacts"
        self._inventory_path = self._root / "inventory.yaml"
        self._inventory_domain_marker_path = self._root / ".inventory-domain-v1"
        self._incident_path = self._root / "last_incident.json"
        self._root_invalid = False
        try:
            self._root_existed_at_start = validate_directory_ancestry(self._root)
            self._root_was_legacy_empty_at_start = (
                _selfmod_root_is_legacy_empty(self._root) if self._root_existed_at_start else True
            )
            ensure_owner_only_directory(self._root)
            ensure_owner_only_directory(self._proposal_dir)
            ensure_owner_only_directory(self._change_dir)
            ensure_owner_only_directory(self._artifact_root)
        except OSError:
            self._root_invalid = True
            self._root_existed_at_start = True
            self._root_was_legacy_empty_at_start = False
        self._state_fault_injector: AtomicWriteFaultInjector | None = None
        self._state_load_result = StateLoadResult(StateLoadStatus.MISSING)
        self._persistence_degradation: AtomicWriteError | None = None
        self._record_load_results: dict[str, StateLoadResult] = {
            "proposal": StateLoadResult(StateLoadStatus.MISSING),
            "change": StateLoadResult(StateLoadStatus.MISSING),
            "incident": StateLoadResult(StateLoadStatus.MISSING),
        }
        self._inventory_domain_marker_status = (
            "invalid" if self._root_invalid else self._inspect_inventory_domain_marker()
        )
        if self._root_invalid:
            self._state_load_result = StateLoadResult(
                StateLoadStatus.CORRUPT,
                reason="invalid_selfmod_root",
            )
            self._inventory = _Inventory()
        else:
            self._inventory = self._load_inventory()
        if not self._root_invalid and self._state_load_result.status is StateLoadStatus.MISSING:
            initial_result = self._state_load_result
            if self._ensure_inventory_domain_marker():
                try:
                    self._persist_inventory_snapshot(self._inventory)
                except AtomicWriteError as exc:
                    self._persistence_degradation = exc
                else:
                    self._state_load_result = initial_result
        elif not self._root_invalid and self._state_load_result.status is StateLoadStatus.OK:
            self._ensure_inventory_domain_marker()
        if self.state_degraded:
            self._block_coupled_skill_authority()
        else:
            self._apply_startup_runtime()

    def propose(self, artifact_path: Path) -> SelfModificationProposal:
        self._require_inventory_available(transition="propose")
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
            manifest=inspection.manifest if inspection.valid else None,
        )
        self._write_record_atomic(
            self._proposal_path(proposal.proposal_id),
            proposal.model_dump(mode="json"),
            record_kind="proposal",
        )
        return SelfModificationProposal.model_validate(proposal.model_dump(mode="json"))

    def apply(self, proposal_id: str, *, confirm: bool) -> SelfModificationApplyResult:
        self._require_inventory_available(transition="apply")
        if not _is_valid_identifier(proposal_id):
            return SelfModificationApplyResult(
                applied=False,
                proposal_id=proposal_id,
                reason="invalid_proposal_id",
            )
        proposal = self._load_proposal(proposal_id)
        if proposal is None:
            load_result = self._record_load_results["proposal"]
            return SelfModificationApplyResult(
                applied=False,
                proposal_id=proposal_id,
                reason=_record_unavailable_reason("proposal", load_result),
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
                warnings=list(proposal.warnings),
                capability_diff=dict(proposal.capability_diff),
                active_version=self._active_version(
                    proposal.artifact_type,
                    proposal.name,
                ),
                reason="artifact_store_copy_failed",
            )

        inspection = self._inspect_artifact(staged_copy.staging_path)
        if not inspection.valid:
            self._discard_staged_artifact(staged_copy)
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
        if proposal.manifest is None or (
            inspection.manifest.model_dump(mode="json") != proposal.manifest.model_dump(mode="json")
        ):
            self._discard_staged_artifact(staged_copy)
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

        try:
            published_copy = self._publish_staged_artifact(staged_copy)
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
        try:
            self._persist_inventory_snapshot(candidate_inventory)
        except AtomicWriteError as exc:
            if not exc.publication_may_have_committed:
                try:
                    self._restore_published_artifact(published_copy)
                except OSError:
                    self._record_incident(
                        proposal_id=proposal.proposal_id,
                        artifact_path=str(published_copy.target_path),
                        reason="artifact_store_restore_failed",
                    )
                    return SelfModificationApplyResult(
                        applied=False,
                        proposal_id=proposal_id,
                        warnings=list(inspection.warnings),
                        capability_diff=dict(inspection.capability_diff),
                        active_version=(
                            previous_entry.active_version if previous_entry.enabled else ""
                        ),
                        reason="artifact_store_restore_failed",
                    )
            return SelfModificationApplyResult(
                applied=False,
                proposal_id=proposal_id,
                warnings=list(inspection.warnings),
                capability_diff=dict(inspection.capability_diff),
                active_version=previous_entry.active_version if previous_entry.enabled else "",
                reason=(
                    "inventory_persistence_uncertain"
                    if exc.publication_may_have_committed
                    else "inventory_persist_failed"
                ),
            )

        try:
            tool_names = self._apply_runtime_for_inventory(
                candidate_inventory,
                proposal.artifact_type,
                proposal.name,
            )
            self._commit_inventory_and_change(candidate_inventory, change)
        except _SelfModificationOperationError as exc:
            if not self._restore_inventory_after_failed_transition(previous_inventory):
                return SelfModificationApplyResult(
                    applied=False,
                    proposal_id=proposal_id,
                    warnings=list(inspection.warnings),
                    capability_diff=dict(inspection.capability_diff),
                    active_version="",
                    reason="inventory_restore_failed",
                )
            try:
                self._restore_published_artifact(published_copy)
            except OSError:
                self._record_incident(
                    proposal_id=proposal.proposal_id,
                    artifact_path=str(published_copy.target_path),
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
        try:
            self._finalize_published_artifact(published_copy)
        except OSError:
            logger.exception(
                "self-modification artifact backup finalization failed for %s",
                published_copy.target_path,
            )
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
        self._require_inventory_available(transition="rollback")
        if not _is_valid_identifier(change_id):
            return SelfModificationRollbackResult(
                rolled_back=False,
                change_id=change_id,
                reason="invalid_change_id",
            )
        change = self._load_change(change_id)
        if change is None:
            load_result = self._record_load_results["change"]
            return SelfModificationRollbackResult(
                rolled_back=False,
                change_id=change_id,
                reason=_record_unavailable_reason("change", load_result),
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
            self._persist_inventory_snapshot(candidate_inventory)
        except AtomicWriteError as exc:
            return SelfModificationRollbackResult(
                rolled_back=False,
                change_id=change_id,
                artifact_type=change.artifact_type,
                name=change.name,
                active_version=self._active_version(change.artifact_type, change.name),
                reason=(
                    "inventory_persistence_uncertain"
                    if exc.publication_may_have_committed
                    else "inventory_persist_failed"
                ),
            )
        try:
            self._apply_runtime_for_inventory(
                candidate_inventory,
                change.artifact_type,
                change.name,
            )
        except _SelfModificationOperationError as exc:
            if not self._restore_inventory_after_failed_transition(current_inventory):
                return SelfModificationRollbackResult(
                    rolled_back=False,
                    change_id=change_id,
                    artifact_type=change.artifact_type,
                    name=change.name,
                    active_version="",
                    reason="inventory_restore_failed",
                )
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
        incident_record = self._load_incident()
        incident = incident_record.model_dump(mode="json") if incident_record is not None else {}
        return {
            "inventory_path": str(self._inventory_path),
            "inventory": self.inventory_state_status(),
            "skills": {
                name: entry.model_dump(mode="json")
                for name, entry in self._inventory.skills.items()
            },
            "behavior_packs": {
                name: entry.model_dump(mode="json")
                for name, entry in self._inventory.behavior_packs.items()
            },
            "incident": incident,
            "records": {
                kind: self._record_state_status(kind) for kind in ("proposal", "change", "incident")
            },
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

    def _apply_startup_runtime(self) -> None:
        for artifact_type, bucket in (
            ("skill_bundle", self._inventory.skills),
            ("behavior_pack", self._inventory.behavior_packs),
        ):
            for name, entry in sorted(bucket.items()):
                if not entry.enabled or not entry.active_version:
                    continue
                try:
                    artifact_path = self._artifact_version_path(
                        artifact_type,
                        name,
                        entry.active_version,
                    )
                except ValueError:
                    self._mark_inventory_degraded("active_artifact_identity_invalid")
                    return
                try:
                    artifact_exists = validate_directory_ancestry(artifact_path)
                except OSError:
                    artifact_exists = False
                if not artifact_exists:
                    self._mark_inventory_degraded("active_artifact_invalid")
                    return
                try:
                    inspection = self._inspect_artifact(artifact_path)
                except Exception:
                    self._mark_inventory_degraded("active_artifact_invalid")
                    return
                if (
                    not inspection.valid
                    or inspection.manifest.type != artifact_type
                    or inspection.manifest.name != name
                    or inspection.manifest.version != entry.active_version
                ):
                    self._mark_inventory_degraded("active_artifact_invalid")
                    return
        for name in sorted(self._inventory.skills):
            try:
                self._apply_runtime_for_inventory(
                    self._inventory,
                    "skill_bundle",
                    name,
                )
            except _SelfModificationOperationError:
                self._mark_inventory_degraded("skill_replay_failed")
                return
        try:
            self._apply_behavior_overlay()
        except Exception:
            self._mark_inventory_degraded("behavior_overlay_failed")

    def _mark_inventory_degraded(self, reason: str) -> None:
        current = self._state_load_result
        self._state_load_result = StateLoadResult(
            StateLoadStatus.CORRUPT,
            reason=reason,
            schema_version=current.schema_version,
            legacy=current.legacy,
        )
        self._block_coupled_skill_authority()

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
        encoded = encode_versioned_json_snapshot(
            inventory.model_dump(mode="json"),
            version=_SELFMOD_INVENTORY_VERSION,
        )
        try:
            atomic_write_bytes(
                self._inventory_path,
                encoded,
                fault_injector=self._state_fault_injector,
            )
        except AtomicWriteError as exc:
            if exc.publication_may_have_committed:
                self._persistence_degradation = exc
                self._block_coupled_skill_authority()
            raise
        self._state_load_result = StateLoadResult(
            StateLoadStatus.OK,
            schema_version=_SELFMOD_INVENTORY_VERSION,
        )

    def _commit_inventory_and_change(
        self,
        inventory: _Inventory,
        change: _ChangeRecord,
    ) -> None:
        _ = inventory
        try:
            self._write_record_atomic(
                self._change_path(change.change_id),
                change.model_dump(mode="json"),
                record_kind="change",
            )
        except AtomicWriteError as exc:
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
        ensure_owner_only_directory(target_path.parent)
        staging_path = target_path.parent / f".{target_path.name}.tmp-{uuid.uuid4().hex}"
        try:
            copy_bounded_regular_tree(
                source_path,
                staging_path,
                max_entries=_ARTIFACT_STAGE_MAX_ENTRIES,
                max_total_bytes=_ARTIFACT_STAGE_MAX_BYTES,
            )
        except OSError:
            if staging_path.exists():
                shutil.rmtree(staging_path, ignore_errors=True)
            raise
        return _StagedArtifactCopy(
            target_path=target_path,
            staging_path=staging_path,
        )

    @staticmethod
    def _remove_artifact_tree(path: Path) -> None:
        remove_owner_controlled_directory_contents(
            path,
            allow_nested_directories=True,
        )
        path.rmdir()

    @classmethod
    def _discard_staged_artifact(cls, staged_copy: _StagedArtifactCopy) -> None:
        if staged_copy.staging_path.exists():
            cls._remove_artifact_tree(staged_copy.staging_path)
            fsync_directory(staged_copy.staging_path.parent)

    @classmethod
    def _publish_staged_artifact(
        cls,
        staged_copy: _StagedArtifactCopy,
    ) -> _PublishedArtifactCopy:
        backup_path = staged_copy.target_path.parent / (
            f".{staged_copy.target_path.name}.bak-{uuid.uuid4().hex}"
        )
        staged_backup: Path | None = None
        try:
            if staged_copy.target_path.exists():
                staged_copy.target_path.replace(backup_path)
                staged_backup = backup_path
            staged_copy.staging_path.replace(staged_copy.target_path)
            fsync_directory(staged_copy.target_path.parent)
        except OSError:
            if staged_copy.target_path.exists():
                cls._remove_artifact_tree(staged_copy.target_path)
            if (
                staged_backup is not None
                and staged_backup.exists()
                and not staged_copy.target_path.exists()
            ):
                staged_backup.replace(staged_copy.target_path)
            if staged_copy.staging_path.exists():
                cls._remove_artifact_tree(staged_copy.staging_path)
            fsync_directory(staged_copy.target_path.parent)
            raise
        return _PublishedArtifactCopy(
            target_path=staged_copy.target_path,
            backup_path=staged_backup,
        )

    @classmethod
    def _restore_published_artifact(cls, published_copy: _PublishedArtifactCopy) -> None:
        if published_copy.target_path.exists():
            cls._remove_artifact_tree(published_copy.target_path)
        if published_copy.backup_path is not None and published_copy.backup_path.exists():
            published_copy.backup_path.replace(published_copy.target_path)
        fsync_directory(published_copy.target_path.parent)

    @classmethod
    def _finalize_published_artifact(cls, published_copy: _PublishedArtifactCopy) -> None:
        if published_copy.backup_path is not None and published_copy.backup_path.exists():
            cls._remove_artifact_tree(published_copy.backup_path)
            fsync_directory(published_copy.target_path.parent)

    def _load_inventory(self) -> _Inventory:
        try:
            target_stat = self._inventory_path.lstat()
        except FileNotFoundError:
            new_or_legacy_empty_domain = not self._root_existed_at_start or (
                self._inventory_domain_marker_status == "missing"
                and self._root_was_legacy_empty_at_start
            )
            self._state_load_result = StateLoadResult(
                StateLoadStatus.MISSING if new_or_legacy_empty_domain else StateLoadStatus.CORRUPT,
                reason=("" if new_or_legacy_empty_domain else "inventory_missing_existing_root"),
            )
            return _Inventory()
        except OSError:
            self._state_load_result = StateLoadResult(
                StateLoadStatus.CORRUPT,
                reason="inventory_stat_failed",
            )
            return _Inventory()
        if not stat.S_ISREG(target_stat.st_mode):
            self._state_load_result = StateLoadResult(
                StateLoadStatus.CORRUPT,
                reason="invalid_inventory_target",
            )
            return _Inventory()
        try:
            raw_bytes = read_owned_regular_file(self._inventory_path, required_mode=0o600)
        except OSError:
            self._state_load_result = StateLoadResult(
                StateLoadStatus.CORRUPT,
                reason="inventory_read_failed",
            )
            return _Inventory()
        if raw_bytes is None:
            self._state_load_result = StateLoadResult(
                StateLoadStatus.CORRUPT,
                reason="inventory_read_failed",
            )
            return _Inventory()

        legacy = False
        document_result, json_payload = decode_json_document(raw_bytes)
        if document_result.status is not StateLoadStatus.OK and raw_bytes.lstrip().startswith(
            (b"{", b"[")
        ):
            self._state_load_result = document_result
            return _Inventory()
        envelope_candidate = (
            isinstance(json_payload, dict)
            and bool({"version", "checksum", "payload"}.intersection(json_payload))
        ) or (json_payload is None and raw_bytes.lstrip().startswith(b"{"))
        if envelope_candidate:
            load_result, payload = decode_versioned_json_snapshot(
                raw_bytes,
                supported_version=_SELFMOD_INVENTORY_VERSION,
            )
            if load_result.status is not StateLoadStatus.OK:
                self._state_load_result = load_result
                return _Inventory()
        else:
            try:
                payload = yaml.safe_load(raw_bytes.decode("utf-8"))
            except (UnicodeError, yaml.YAMLError, RecursionError):
                self._state_load_result = StateLoadResult(
                    StateLoadStatus.CORRUPT,
                    reason="invalid_yaml",
                )
                return _Inventory()
            load_result = StateLoadResult(StateLoadStatus.OK, legacy=True)
            legacy = True
        if not isinstance(payload, dict):
            self._state_load_result = StateLoadResult(
                StateLoadStatus.CORRUPT,
                reason="invalid_inventory_payload",
                schema_version=load_result.schema_version,
                legacy=legacy,
            )
            return _Inventory()
        if set(payload) != {"skills", "behavior_packs"}:
            self._state_load_result = StateLoadResult(
                StateLoadStatus.CORRUPT,
                reason="invalid_inventory_payload",
                schema_version=load_result.schema_version,
                legacy=legacy,
            )
            return _Inventory()
        try:
            inventory = _Inventory.model_validate(payload)
        except ValidationError:
            self._state_load_result = StateLoadResult(
                StateLoadStatus.CORRUPT,
                reason="invalid_inventory_entry",
                schema_version=load_result.schema_version,
                legacy=legacy,
            )
            return _Inventory()
        for bucket in (inventory.skills, inventory.behavior_packs):
            for name, entry in bucket.items():
                if (
                    not _ARTIFACT_NAME_RE.fullmatch(name)
                    or (entry.enabled and not entry.active_version)
                    or (
                        entry.active_version
                        and not _ARTIFACT_VERSION_RE.fullmatch(entry.active_version)
                    )
                ):
                    self._state_load_result = StateLoadResult(
                        StateLoadStatus.CORRUPT,
                        reason="invalid_inventory_entry",
                        schema_version=load_result.schema_version,
                        legacy=legacy,
                    )
                    return _Inventory()
        self._state_load_result = load_result
        return inventory

    def _inspect_inventory_domain_marker(self) -> str:
        try:
            target_stat = self._inventory_domain_marker_path.lstat()
        except FileNotFoundError:
            return "missing"
        except OSError:
            return "invalid"
        if not stat.S_ISREG(target_stat.st_mode):
            return "invalid"
        try:
            marker = read_owned_regular_file(
                self._inventory_domain_marker_path,
                required_mode=0o600,
            )
        except OSError:
            return "invalid"
        if marker is None:
            return "invalid"
        return "valid" if marker == _SELFMOD_INVENTORY_DOMAIN_MARKER else "invalid"

    def _ensure_inventory_domain_marker(self) -> bool:
        if self._inventory_domain_marker_status == "valid":
            return True
        if self._inventory_domain_marker_status == "invalid":
            self._state_load_result = StateLoadResult(
                StateLoadStatus.CORRUPT,
                reason="invalid_inventory_domain_marker",
            )
            return False
        try:
            atomic_write_bytes(
                self._inventory_domain_marker_path,
                _SELFMOD_INVENTORY_DOMAIN_MARKER,
                fault_injector=self._state_fault_injector,
            )
        except AtomicWriteError as exc:
            self._persistence_degradation = exc
            return False
        self._inventory_domain_marker_status = "valid"
        return True

    def _persist_inventory(self) -> None:
        self._persist_inventory_snapshot(self._inventory)

    @property
    def state_degraded(self) -> bool:
        return self._persistence_degradation is not None or self._state_load_result.status in {
            StateLoadStatus.CORRUPT,
            StateLoadStatus.UNSUPPORTED_SCHEMA,
        }

    def inventory_load_result(self) -> StateLoadResult:
        return self._state_load_result

    def reset_state(self) -> tuple[int, int]:
        """Reset self-modification artifacts and typed control state together."""

        entry_count = len(self._inventory.skills) + len(self._inventory.behavior_packs)
        try:
            artifact_count = remove_owner_controlled_directory_contents(
                self._root,
                allow_nested_directories=True,
            )
            self._inventory = _Inventory()
            self._root_invalid = False
            self._inventory_domain_marker_status = "missing"
            self._state_load_result = StateLoadResult(StateLoadStatus.MISSING)
            self._persistence_degradation = None
            self._record_load_results = {
                "proposal": StateLoadResult(StateLoadStatus.MISSING),
                "change": StateLoadResult(StateLoadStatus.MISSING),
                "incident": StateLoadResult(StateLoadStatus.MISSING),
            }
            ensure_owner_only_directory(self._root)
            ensure_owner_only_directory(self._proposal_dir)
            ensure_owner_only_directory(self._change_dir)
            ensure_owner_only_directory(self._artifact_root)
            if not self._ensure_inventory_domain_marker():
                degradation = self._persistence_degradation
                if degradation is not None:
                    raise degradation
                raise RuntimeError("selfmod inventory reset marker publication failed")
            self._persist_inventory_snapshot(self._inventory)
        except Exception as exc:
            if isinstance(exc, AtomicWriteError):
                self._persistence_degradation = exc
            self._mark_reset_failed(apply_empty_overlay=True)
            raise
        try:
            self._apply_behavior_overlay()
        except Exception:
            self._mark_reset_failed(apply_empty_overlay=False)
            raise
        self._state_load_result = StateLoadResult(
            StateLoadStatus.OK,
            schema_version=_SELFMOD_INVENTORY_VERSION,
        )
        return entry_count, artifact_count

    def _mark_reset_failed(self, *, apply_empty_overlay: bool) -> None:
        self._inventory = _Inventory()
        self._root_invalid = True
        self._inventory_domain_marker_status = "invalid"
        self._state_load_result = StateLoadResult(
            StateLoadStatus.CORRUPT,
            reason="reset_failed",
        )
        self._record_load_results = {
            "proposal": StateLoadResult(StateLoadStatus.CORRUPT, reason="reset_failed"),
            "change": StateLoadResult(StateLoadStatus.CORRUPT, reason="reset_failed"),
            "incident": StateLoadResult(StateLoadStatus.CORRUPT, reason="reset_failed"),
        }
        self._block_coupled_skill_authority()
        if apply_empty_overlay:
            with suppress(Exception):
                self._apply_behavior_overlay()

    def inventory_state_status(self) -> dict[str, Any]:
        load_result = self._state_load_result
        persistence = self._persistence_degradation
        problems: list[str] = []
        if persistence is not None:
            problems.append("selfmod_inventory_persistence_degraded")
        elif load_result.status in {
            StateLoadStatus.CORRUPT,
            StateLoadStatus.UNSUPPORTED_SCHEMA,
        }:
            problems.append(f"selfmod_inventory_{load_result.status.value}")
        return {
            "status": "degraded" if self.state_degraded else "ok",
            "problems": problems,
            "path": str(self._inventory_path),
            "load_status": load_result.status.value,
            "reason": load_result.reason,
            "schema_version": load_result.schema_version,
            "legacy": load_result.legacy,
            "fail_closed": self.state_degraded,
            "stage": persistence.stage.value if persistence is not None else "",
            "remediation": (
                "Restore the self-modification inventory from a trusted backup, or remove "
                "it only after verifying that no self-modified artifacts should remain "
                "active, then restart shisad."
                if self.state_degraded
                else ""
            ),
        }

    def doctor_status(self) -> dict[str, Any]:
        self._load_incident()
        inventory_status = self.inventory_state_status()
        records = {
            kind: self._record_state_status(kind) for kind in ("proposal", "change", "incident")
        }
        problems = list(inventory_status["problems"])
        for kind, record_status in records.items():
            load_status = str(record_status["load_status"])
            if load_status in {
                StateLoadStatus.CORRUPT.value,
                StateLoadStatus.UNSUPPORTED_SCHEMA.value,
            }:
                problems.append(f"selfmod_{kind}_{load_status}")
        return {
            **inventory_status,
            "status": "degraded" if problems else "ok",
            "problems": problems,
            "records": records,
        }

    def _require_inventory_available(self, *, transition: str) -> None:
        persistence = self._persistence_degradation
        if persistence is not None:
            raise StatePersistenceDegradedError(
                authority="selfmod_inventory",
                transition=transition,
                stage=persistence.stage.value,
                reason=(
                    "commit_uncertain"
                    if persistence.publication_may_have_committed
                    else "publication_failed"
                ),
            )
        load_result = self._state_load_result
        if load_result.status in {
            StateLoadStatus.CORRUPT,
            StateLoadStatus.UNSUPPORTED_SCHEMA,
        }:
            raise StatePersistenceDegradedError(
                authority="selfmod_inventory",
                transition=transition,
                stage="load",
                reason=load_result.reason or load_result.status.value,
            )

    def _block_coupled_skill_authority(self) -> None:
        blocker = getattr(self._skill_manager, "degrade_from_external_authority", None)
        if callable(blocker):
            persistence = self._persistence_degradation
            blocker(
                authority="selfmod_inventory",
                reason=(
                    "commit_uncertain"
                    if persistence is not None and persistence.publication_may_have_committed
                    else self._state_load_result.reason or "persistence_uncertain"
                ),
            )

    def _proposal_path(self, proposal_id: str) -> Path:
        return self._proposal_dir / f"{proposal_id}.json"

    def _change_path(self, change_id: str) -> Path:
        return self._change_dir / f"{change_id}.json"

    def _load_proposal(self, proposal_id: str) -> _ProposalRecord | None:
        if not _is_valid_identifier(proposal_id):
            return None
        record = self._load_record(
            self._proposal_path(proposal_id),
            model_type=_ProposalRecord,
            record_kind="proposal",
        )
        if record is not None and record.proposal_id != proposal_id:
            self._mark_record_corrupt("proposal", "record_identity_mismatch")
            return None
        return record

    def _load_change(self, change_id: str) -> _ChangeRecord | None:
        if not _is_valid_identifier(change_id):
            return None
        record = self._load_record(
            self._change_path(change_id),
            model_type=_ChangeRecord,
            record_kind="change",
        )
        if record is not None and record.change_id != change_id:
            self._mark_record_corrupt("change", "record_identity_mismatch")
            return None
        return record

    def _load_incident(self) -> _IncidentRecord | None:
        return self._load_record(
            self._incident_path,
            model_type=_IncidentRecord,
            record_kind="incident",
        )

    def _write_record_atomic(
        self,
        path: Path,
        payload: dict[str, Any],
        *,
        record_kind: str,
    ) -> None:
        try:
            atomic_write_bytes(
                path,
                encode_versioned_json_snapshot(payload, version=1),
                fault_injector=self._state_fault_injector,
            )
        except AtomicWriteError:
            raise
        self._record_load_results[record_kind] = StateLoadResult(
            StateLoadStatus.OK,
            schema_version=1,
        )

    def _load_record(
        self,
        path: Path,
        *,
        model_type: type[BaseModel],
        record_kind: str,
    ) -> Any | None:
        try:
            target_stat = path.lstat()
        except FileNotFoundError:
            self._record_load_results[record_kind] = StateLoadResult(StateLoadStatus.MISSING)
            return None
        except OSError:
            self._record_load_results[record_kind] = StateLoadResult(
                StateLoadStatus.CORRUPT,
                reason="record_stat_failed",
            )
            return None
        if not stat.S_ISREG(target_stat.st_mode):
            self._record_load_results[record_kind] = StateLoadResult(
                StateLoadStatus.CORRUPT,
                reason="invalid_record_target",
            )
            return None
        try:
            raw_bytes = read_owned_regular_file(path, required_mode=0o600)
        except OSError:
            self._record_load_results[record_kind] = StateLoadResult(
                StateLoadStatus.CORRUPT,
                reason="record_read_failed",
            )
            return None
        if raw_bytes is None:
            self._record_load_results[record_kind] = StateLoadResult(
                StateLoadStatus.CORRUPT,
                reason="record_read_failed",
            )
            return None
        document_result, raw_payload = decode_json_document(raw_bytes)
        envelope_candidate = (
            isinstance(raw_payload, dict)
            and (
                "checksum" in raw_payload
                or "payload" in raw_payload
                or (
                    isinstance(raw_payload.get("version"), int)
                    and not isinstance(raw_payload.get("version"), bool)
                )
            )
        ) or (raw_payload is None and raw_bytes.lstrip().startswith(b"{"))
        if isinstance(raw_payload, dict) and not envelope_candidate:
            load_result = StateLoadResult(StateLoadStatus.OK, legacy=True)
            payload: Any = raw_payload
        else:
            if (
                document_result.status is not StateLoadStatus.OK
                and not raw_bytes.lstrip().startswith(b"{")
            ):
                self._record_load_results[record_kind] = document_result
                return None
            load_result, payload = decode_versioned_json_snapshot(
                raw_bytes,
                supported_version=1,
            )
            if load_result.status is not StateLoadStatus.OK:
                self._record_load_results[record_kind] = load_result
                return None
        if not isinstance(payload, dict):
            self._record_load_results[record_kind] = StateLoadResult(
                StateLoadStatus.CORRUPT,
                reason="invalid_record_payload",
                schema_version=load_result.schema_version,
                legacy=load_result.legacy,
            )
            return None
        try:
            record = model_type.model_validate(payload)
        except ValidationError:
            self._record_load_results[record_kind] = StateLoadResult(
                StateLoadStatus.CORRUPT,
                reason="invalid_record_entry",
                schema_version=load_result.schema_version,
                legacy=load_result.legacy,
            )
            return None
        self._record_load_results[record_kind] = load_result
        return record

    def _record_state_status(self, record_kind: str) -> dict[str, Any]:
        load_result = self._record_load_results[record_kind]
        return {
            "load_status": load_result.status.value,
            "reason": load_result.reason,
            "schema_version": load_result.schema_version,
            "legacy": load_result.legacy,
        }

    def _mark_record_corrupt(self, record_kind: str, reason: str) -> None:
        current = self._record_load_results[record_kind]
        self._record_load_results[record_kind] = StateLoadResult(
            StateLoadStatus.CORRUPT,
            reason=reason,
            schema_version=current.schema_version,
            legacy=current.legacy,
        )

    def _restore_inventory_after_failed_transition(self, inventory: _Inventory) -> bool:
        try:
            self._persist_inventory_snapshot(inventory)
        except AtomicWriteError as exc:
            self._persistence_degradation = exc
            self._block_coupled_skill_authority()
            return False
        return True

    def _artifact_version_path(self, artifact_type: str, name: str, version: str) -> Path:
        if not _ARTIFACT_NAME_RE.fullmatch(name) or not _ARTIFACT_VERSION_RE.fullmatch(version):
            raise ValueError("unsafe_artifact_identity")
        bucket = "skills" if artifact_type == "skill_bundle" else "behavior_packs"
        return self._artifact_root / bucket / name / version

    def _record_incident(self, *, proposal_id: str, artifact_path: str, reason: str) -> None:
        record = _IncidentRecord(
            proposal_id=proposal_id,
            artifact_path=artifact_path,
            reason=reason,
            recorded_at=datetime.now(UTC).isoformat(),
        )
        self._write_record_atomic(
            self._incident_path,
            record.model_dump(mode="json"),
            record_kind="incident",
        )


def _selfmod_root_is_legacy_empty(path: Path) -> bool:
    allowed_children = {"proposals", "changes", "artifacts"}
    try:
        children = list(path.iterdir())
    except OSError:
        return False
    for child in children:
        if child.name not in allowed_children:
            return False
        try:
            child_stat = child.lstat()
            if not stat.S_ISDIR(child_stat.st_mode) or next(child.iterdir(), None) is not None:
                return False
        except OSError:
            return False
    return True


def _is_valid_identifier(value: str) -> bool:
    return _IDENTIFIER_RE.fullmatch(value.strip()) is not None


def _normalize_integrity_reason(reason: str) -> str:
    normalized = reason.strip() or "integrity_mismatch"
    if normalized.startswith("file_"):
        return "integrity_mismatch"
    return normalized


def _record_unavailable_reason(record_kind: str, load_result: StateLoadResult) -> str:
    if load_result.status is StateLoadStatus.CORRUPT:
        return f"{record_kind}_corrupt"
    if load_result.status is StateLoadStatus.UNSUPPORTED_SCHEMA:
        return f"{record_kind}_unsupported_schema"
    return f"{record_kind}_not_found"


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
