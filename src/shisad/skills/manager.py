"""Skill installation manager with disclosure, vetting, and lifecycle gates."""

from __future__ import annotations

import json
import logging
import stat
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, ValidationError

from shisad.core.atomic_state import (
    AtomicWriteError,
    AtomicWriteFaultInjector,
    StateLoadResult,
    StateLoadStatus,
    StatePersistenceDegradedError,
    atomic_write_bytes,
    decode_versioned_json_snapshot,
    encode_versioned_json_snapshot,
)
from shisad.core.events import SkillToolRegistrationDropped
from shisad.core.tools.registry import ToolRegistry
from shisad.core.tools.schema import ToolDefinition, ToolRetryClass
from shisad.core.types import Capability, ToolName
from shisad.security.policy import SkillPolicy
from shisad.skills.analyzer import (
    CapabilityInferenceAnalyzer,
    DangerousPatternAnalyzer,
    Finding,
    FindingSeverity,
    ObfuscationAnalyzer,
    SkillBundle,
    ToolSurfaceAnalyzer,
    load_skill_bundle,
)
from shisad.skills.artifacts import ArtifactState
from shisad.skills.cross_skill import scan_cross_skill
from shisad.skills.disclosure import diff_versions, list_files, render_risk_summary
from shisad.skills.llm_analyzer import LlmSkillAnalyzer
from shisad.skills.meta_analyzer import MetaAnalyzer
from shisad.skills.profile import SkillProfiler
from shisad.skills.sandbox import SkillExecutionRequest, SkillRuntimeSandbox, SkillSandboxDecision
from shisad.skills.signatures import KeyRing, SignatureStatus, verify_manifest_signature

logger = logging.getLogger(__name__)

_SKILL_INVENTORY_VERSION = 1


class SkillInstallDecision(BaseModel):
    allowed: bool
    status: str
    reason: str = ""
    findings: list[Finding] = Field(default_factory=list)
    summary: str = ""
    artifact_state: ArtifactState = ArtifactState.DRAFT


class InstalledSkill(BaseModel):
    name: str
    version: str
    path: str
    manifest_hash: str
    state: ArtifactState
    author: str
    tool_schema_hashes: dict[str, str] = Field(default_factory=dict)
    tool_schema_hashes_legacy: bool = False


class SkillManager:
    """High-level workflow for skill review/install/profile operations."""

    def __init__(
        self,
        *,
        storage_dir: Path,
        policy: SkillPolicy | None = None,
        keyring: KeyRing | None = None,
        llm_analyzer: LlmSkillAnalyzer | None = None,
        tool_registry: ToolRegistry | None = None,
    ) -> None:
        self._storage_dir = storage_dir
        self._storage_dir.mkdir(parents=True, exist_ok=True)
        self._inventory_path = self._storage_dir / "inventory.json"
        self._policy = policy or SkillPolicy()
        self._keyring = keyring or KeyRing()
        self._llm_analyzer = llm_analyzer
        self._tool_registry = tool_registry
        self._state_fault_injector: AtomicWriteFaultInjector | None = None
        self._state_load_result = StateLoadResult(StateLoadStatus.MISSING)
        self._persistence_degradation: AtomicWriteError | None = None
        self._external_degradation: tuple[str, str] | None = None
        self._dangerous = DangerousPatternAnalyzer()
        self._tool_surface = ToolSurfaceAnalyzer()
        self._capability = CapabilityInferenceAnalyzer()
        self._obfuscation = ObfuscationAnalyzer()
        self._meta = MetaAnalyzer()
        self._runtime_sandbox = SkillRuntimeSandbox(
            skills_root=self._storage_dir.parent / "skills",
            config_root=self._storage_dir.parent,
        )
        self._inventory = self._load_inventory()
        self._skill_tool_map: dict[str, list[ToolName]] = {}
        self._pending_registration_events: list[SkillToolRegistrationDropped] = []
        self._register_inventory_tools()

    def review(self, skill_path: Path) -> dict[str, Any]:
        bundle = load_skill_bundle(
            skill_path,
            allowed_dependency_sources=set(self._policy.dependency_source_allowlist),
        )
        findings = self._run_static(bundle)
        content_map = {file.path: file.content for file in bundle.files if not file.binary}
        findings = self._meta.filter(findings, content_map=content_map)
        signature = verify_manifest_signature(
            manifest=bundle.manifest,
            file_hashes={file.path: file.sha256 for file in bundle.files},
            keyring=self._keyring,
        )
        prior = self._inventory.get(bundle.manifest.name)
        diff = []
        if prior is not None and Path(prior.path).exists():
            previous = load_skill_bundle(
                Path(prior.path),
                allowed_dependency_sources=set(self._policy.dependency_source_allowlist),
            )
            diff = diff_versions(previous, bundle, findings=findings)
        return {
            "manifest": bundle.manifest.model_dump(mode="json"),
            "files": [item.model_dump(mode="json") for item in list_files(bundle)],
            "findings": [item.model_dump(mode="json") for item in findings],
            "signature": signature.status.value,
            "signature_reason": signature.reason,
            "summary": render_risk_summary(skill=bundle, findings=findings, signature=signature),
            "diff": [item.model_dump(mode="json") for item in diff],
        }

    async def install(
        self,
        skill_path: Path,
        *,
        approve_untrusted: bool = False,
    ) -> SkillInstallDecision:
        self._require_state_available(transition="install")
        bundle = load_skill_bundle(
            skill_path,
            allowed_dependency_sources=set(self._policy.dependency_source_allowlist),
        )
        findings = self._run_static(bundle)
        if self._llm_analyzer is not None:
            llm_findings = await self._llm_analyzer.analyze(
                bundle,
                static_risk_score=_risk_score(findings),
            )
            findings.extend(llm_findings)
        findings.extend(scan_cross_skill([bundle, *self._installed_bundles()]))
        content_map = {file.path: file.content for file in bundle.files if not file.binary}
        findings = self._meta.filter(findings, content_map=content_map)
        signature = verify_manifest_signature(
            manifest=bundle.manifest,
            file_hashes={file.path: file.sha256 for file in bundle.files},
            keyring=self._keyring,
        )
        summary = render_risk_summary(skill=bundle, findings=findings, signature=signature)

        if signature.status == SignatureStatus.INVALID:
            return SkillInstallDecision(
                allowed=False,
                status="blocked",
                reason=signature.reason,
                findings=findings,
                summary=summary,
                artifact_state=ArtifactState.REVOKED,
            )
        if (
            self._policy.require_signature_for_auto_install
            and signature.status is not SignatureStatus.TRUSTED
        ):
            return SkillInstallDecision(
                allowed=False,
                status="review",
                reason="signature_required_policy",
                findings=findings,
                summary=summary,
                artifact_state=ArtifactState.REVIEW,
            )
        if signature.require_confirmation and not approve_untrusted:
            return SkillInstallDecision(
                allowed=False,
                status="review",
                reason=signature.reason,
                findings=findings,
                summary=summary,
                artifact_state=ArtifactState.REVIEW,
            )

        max_severity = _max_severity(findings)
        if max_severity in {FindingSeverity.CRITICAL, FindingSeverity.HIGH}:
            if any("tool_surface_policy" in finding.tags for finding in findings):
                return SkillInstallDecision(
                    allowed=False,
                    status="review",
                    reason="tool_surface_policy_violation",
                    findings=findings,
                    summary=summary,
                    artifact_state=ArtifactState.REVIEW,
                )
            return SkillInstallDecision(
                allowed=False,
                status="review",
                reason="high_risk_findings",
                findings=findings,
                summary=summary,
                artifact_state=ArtifactState.REVIEW,
            )

        existing = self._inventory.get(bundle.manifest.name)
        if existing is not None and self._policy.require_review_on_update:
            return SkillInstallDecision(
                allowed=False,
                status="review",
                reason="update_requires_review",
                findings=findings,
                summary=summary,
                artifact_state=ArtifactState.REVIEW,
            )

        self.activate_bundle(skill_path)
        return SkillInstallDecision(
            allowed=True,
            status="installed",
            reason="ok",
            findings=findings,
            summary=summary,
            artifact_state=ArtifactState.PUBLISHED,
        )

    def profile(self, skill_path: Path) -> SkillProfiler:
        bundle = load_skill_bundle(
            skill_path,
            allowed_dependency_sources=set(self._policy.dependency_source_allowlist),
        )
        inferred = self._capability.infer(bundle)
        profiler = SkillProfiler()
        for host in inferred.network_domains:
            profiler.record_network(host)
        for path in inferred.file_paths:
            profiler.record_filesystem(path)
        for command in inferred.shell_commands:
            profiler.record_shell(command)
        for env_name in inferred.environment_vars:
            profiler.record_environment(env_name)
        return profiler

    def list_installed(self) -> list[InstalledSkill]:
        self._require_state_available(transition="list")
        return sorted(self._inventory.values(), key=lambda item: item.name)

    def revoke(self, *, skill_name: str, reason: str = "") -> InstalledSkill | None:
        self._require_state_available(transition="revoke")
        installed = self._inventory.get(skill_name)
        if installed is None:
            return None
        if installed.state == ArtifactState.REVOKED:
            return installed
        updated = installed.model_copy(update={"state": ArtifactState.REVOKED})
        candidate = dict(self._inventory)
        candidate[skill_name] = updated
        self._persist_inventory_snapshot(candidate)
        self._inventory = candidate
        self._unregister_skill_tools(skill_name)
        _ = reason
        return updated

    def activate_bundle(
        self,
        skill_path: Path,
        *,
        state: ArtifactState = ArtifactState.PUBLISHED,
    ) -> InstalledSkill | None:
        self._require_state_available(transition="activate")
        bundle = load_skill_bundle(
            skill_path,
            allowed_dependency_sources=set(self._policy.dependency_source_allowlist),
        )
        installed = InstalledSkill(
            name=bundle.manifest.name,
            version=bundle.manifest.version,
            path=str(skill_path),
            manifest_hash=bundle.manifest.manifest_hash(),
            state=state,
            author=bundle.manifest.author,
            tool_schema_hashes=_declared_tool_schema_hashes(bundle.manifest),
        )
        candidate = dict(self._inventory)
        candidate[bundle.manifest.name] = installed
        self._persist_inventory_snapshot(candidate)
        self._inventory = candidate
        self._unregister_skill_tools(bundle.manifest.name)
        if state == ArtifactState.PUBLISHED:
            self._register_skill_tools(
                bundle.manifest,
                expected_hashes=installed.tool_schema_hashes,
                registration_source="activate_bundle",
            )
        return installed

    def tool_names_for_skill(self, skill_name: str) -> list[str]:
        return [str(name) for name in self._skill_tool_map.get(skill_name, [])]

    def drain_registration_events(self) -> list[SkillToolRegistrationDropped]:
        events = list(self._pending_registration_events)
        self._pending_registration_events.clear()
        return events

    def authorize_runtime(
        self,
        *,
        skill_name: str,
        request: SkillExecutionRequest,
    ) -> SkillSandboxDecision:
        self._require_state_available(transition="authorize_runtime")
        installed = self._inventory.get(skill_name)
        if installed is None:
            return SkillSandboxDecision(allowed=False, reason="unknown_skill")
        if installed.state != ArtifactState.PUBLISHED:
            return SkillSandboxDecision(allowed=False, reason="skill_not_published")
        path = Path(installed.path)
        if not path.exists():
            return SkillSandboxDecision(allowed=False, reason="skill_path_missing")
        bundle = load_skill_bundle(
            path,
            allowed_dependency_sources=set(self._policy.dependency_source_allowlist),
        )
        manifest_hash = bundle.manifest.manifest_hash()
        if manifest_hash != installed.manifest_hash:
            return SkillSandboxDecision(allowed=False, reason="skill_manifest_drift")
        current_tool_hashes = _declared_tool_schema_hashes(bundle.manifest)
        if current_tool_hashes != dict(installed.tool_schema_hashes):
            return SkillSandboxDecision(allowed=False, reason="skill_tool_schema_drift")
        return self._runtime_sandbox.authorize(
            bundle.manifest,
            request.model_copy(update={"skill_name": bundle.manifest.name}),
        )

    def _run_static(self, bundle: SkillBundle) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._dangerous.analyze(bundle))
        findings.extend(self._tool_surface.analyze(bundle))
        findings.extend(self._obfuscation.analyze(bundle))
        findings.extend(self._capability.analyze(bundle))
        return findings

    @property
    def state_degraded(self) -> bool:
        return (
            self._persistence_degradation is not None
            or self._external_degradation is not None
            or self._state_load_result.status
            in {
                StateLoadStatus.CORRUPT,
                StateLoadStatus.UNSUPPORTED_SCHEMA,
            }
        )

    def degrade_from_external_authority(self, *, authority: str, reason: str) -> None:
        """Withdraw dynamic tools when a coupled activation authority is uncertain."""

        self._external_degradation = (authority, reason)
        self._unregister_all_skill_tools()

    def inventory_load_result(self) -> StateLoadResult:
        return self._state_load_result

    def state_status(self) -> dict[str, Any]:
        load_result = self._state_load_result
        problems: list[str] = []
        if self._persistence_degradation is not None:
            problems.append("skill_inventory_persistence_degraded")
        elif self._external_degradation is not None:
            problems.append("skill_inventory_external_authority_degraded")
        elif load_result.status in {
            StateLoadStatus.CORRUPT,
            StateLoadStatus.UNSUPPORTED_SCHEMA,
        }:
            problems.append(f"skill_inventory_{load_result.status.value}")
        external = self._external_degradation
        remediation = ""
        if external is not None:
            remediation = (
                f"Restore the coupled {external[0]} authority from a trusted backup or "
                "explicitly reset that state domain after verification, then restart shisad."
            )
        elif self.state_degraded:
            remediation = (
                "Restore the skill inventory from a trusted backup, or remove it only after "
                "verifying that no skills should remain active, then restart shisad."
            )
        persistence = self._persistence_degradation
        return {
            "status": "degraded" if self.state_degraded else "ok",
            "problems": problems,
            "path": str(self._inventory_path),
            "load_status": load_result.status.value,
            "reason": load_result.reason or (external[1] if external is not None else ""),
            "schema_version": load_result.schema_version,
            "legacy": load_result.legacy,
            "fail_closed": self.state_degraded,
            "stage": (
                persistence.stage.value
                if persistence is not None
                else "external"
                if external is not None
                else ""
            ),
            "remediation": remediation,
        }

    def _require_state_available(self, *, transition: str) -> None:
        external = self._external_degradation
        if external is not None:
            raise StatePersistenceDegradedError(
                authority=external[0],
                transition=transition,
                stage="external",
                reason=external[1],
            )
        persistence = self._persistence_degradation
        if persistence is not None:
            raise StatePersistenceDegradedError(
                authority="skill_inventory",
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
                authority="skill_inventory",
                transition=transition,
                stage="load",
                reason=load_result.reason or load_result.status.value,
            )

    def _load_inventory(self) -> dict[str, InstalledSkill]:
        try:
            target_stat = self._inventory_path.lstat()
        except FileNotFoundError:
            self._state_load_result = StateLoadResult(StateLoadStatus.MISSING)
            return {}
        except OSError:
            self._state_load_result = StateLoadResult(
                StateLoadStatus.CORRUPT,
                reason="inventory_stat_failed",
            )
            return {}
        if not stat.S_ISREG(target_stat.st_mode):
            self._state_load_result = StateLoadResult(
                StateLoadStatus.CORRUPT,
                reason="invalid_inventory_target",
            )
            return {}
        try:
            raw_bytes = self._inventory_path.read_bytes()
        except OSError:
            self._state_load_result = StateLoadResult(
                StateLoadStatus.CORRUPT,
                reason="inventory_read_failed",
            )
            return {}

        legacy = False
        try:
            raw_payload = json.loads(raw_bytes.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError):
            raw_payload = None
        if isinstance(raw_payload, list):
            payload: Any = raw_payload
            load_result = StateLoadResult(StateLoadStatus.OK, legacy=True)
            legacy = True
        else:
            load_result, payload = decode_versioned_json_snapshot(
                raw_bytes,
                supported_version=_SKILL_INVENTORY_VERSION,
            )
            if load_result.status is not StateLoadStatus.OK:
                self._state_load_result = load_result
                return {}
        if not isinstance(payload, list):
            self._state_load_result = StateLoadResult(
                StateLoadStatus.CORRUPT,
                reason="invalid_inventory_payload",
                schema_version=load_result.schema_version,
                legacy=legacy,
            )
            return {}

        inventory: dict[str, InstalledSkill] = {}
        missing_binding_map = False
        invalid_binding_map = False
        for item in payload:
            if not isinstance(item, dict):
                self._state_load_result = StateLoadResult(
                    StateLoadStatus.CORRUPT,
                    reason="invalid_inventory_entry",
                    schema_version=load_result.schema_version,
                    legacy=legacy,
                )
                return {}
            candidate_item = dict(item)
            if legacy:
                candidate_item["tool_schema_hashes_legacy"] = True
            try:
                entry = InstalledSkill.model_validate(candidate_item)
            except (TypeError, ValueError, ValidationError):
                self._state_load_result = StateLoadResult(
                    StateLoadStatus.CORRUPT,
                    reason="invalid_inventory_entry",
                    schema_version=load_result.schema_version,
                    legacy=legacy,
                )
                return {}
            if not all(
                value.strip()
                for value in (
                    entry.name,
                    entry.version,
                    entry.path,
                    entry.manifest_hash,
                    entry.author,
                )
            ):
                self._state_load_result = StateLoadResult(
                    StateLoadStatus.CORRUPT,
                    reason="invalid_inventory_entry",
                    schema_version=load_result.schema_version,
                    legacy=legacy,
                )
                return {}
            if entry.name in inventory:
                self._state_load_result = StateLoadResult(
                    StateLoadStatus.CORRUPT,
                    reason="duplicate_skill_name",
                    schema_version=load_result.schema_version,
                    legacy=legacy,
                )
                return {}
            inventory[entry.name] = entry
            if not legacy and "tool_schema_hashes" not in item:
                missing_binding_map = True
            if (
                not entry.tool_schema_hashes_legacy
                and any(not value.strip() for value in entry.tool_schema_hashes.values())
            ):
                invalid_binding_map = True
        if missing_binding_map:
            self._state_load_result = StateLoadResult(
                StateLoadStatus.CORRUPT,
                reason="missing_tool_schema_bindings",
                schema_version=load_result.schema_version,
            )
            return {}
        if invalid_binding_map:
            self._state_load_result = StateLoadResult(
                StateLoadStatus.CORRUPT,
                reason="invalid_tool_schema_bindings",
                schema_version=load_result.schema_version,
            )
            return {}
        self._state_load_result = StateLoadResult(
            load_result.status,
            reason=load_result.reason,
            schema_version=load_result.schema_version,
            legacy=legacy
            or any(entry.tool_schema_hashes_legacy for entry in inventory.values()),
        )
        return inventory

    def _persist_inventory_snapshot(self, inventory: dict[str, InstalledSkill]) -> None:
        payload = [
            entry.model_dump(mode="json")
            for entry in sorted(inventory.values(), key=lambda item: item.name)
        ]
        encoded = encode_versioned_json_snapshot(
            payload,
            version=_SKILL_INVENTORY_VERSION,
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
                self._unregister_all_skill_tools()
            raise
        self._state_load_result = StateLoadResult(
            StateLoadStatus.OK,
            schema_version=_SKILL_INVENTORY_VERSION,
            legacy=any(entry.tool_schema_hashes_legacy for entry in inventory.values()),
        )

    def _installed_bundles(self) -> list[SkillBundle]:
        bundles: list[SkillBundle] = []
        for skill in self._inventory.values():
            path = Path(skill.path)
            if not path.exists():
                continue
            try:
                bundles.append(
                    load_skill_bundle(
                        path,
                        allowed_dependency_sources=set(self._policy.dependency_source_allowlist),
                    )
                )
            except (FileNotFoundError, OSError, TypeError, ValueError):
                continue
        return bundles

    def _register_inventory_tools(self) -> None:
        if self.state_degraded:
            return
        inventory_migrated = False
        candidate = dict(self._inventory)
        registration_bundles: list[tuple[InstalledSkill, SkillBundle]] = []
        for installed in self._inventory.values():
            if installed.state != ArtifactState.PUBLISHED:
                continue
            path = Path(installed.path)
            if not path.exists():
                continue
            try:
                bundle = load_skill_bundle(
                    path,
                    allowed_dependency_sources=set(self._policy.dependency_source_allowlist),
                )
            except (FileNotFoundError, OSError, TypeError, ValueError):
                continue
            if not _tool_schema_bindings_complete(
                bundle.manifest,
                expected_hashes=installed.tool_schema_hashes,
            ):
                if installed.tool_schema_hashes_legacy:
                    logger.warning(
                        "Skipping unbound legacy skill tools until the skill is reviewed "
                        "again: skill=%s version=%s",
                        installed.name,
                        installed.version,
                    )
                    continue
                self._state_load_result = StateLoadResult(
                    StateLoadStatus.CORRUPT,
                    reason="invalid_tool_schema_bindings",
                    schema_version=_SKILL_INVENTORY_VERSION,
                )
                self._unregister_all_skill_tools()
                return
            registration_bundles.append((installed, bundle))
            migrated_hashes = _migrated_tool_schema_hashes(
                bundle.manifest,
                expected_hashes=installed.tool_schema_hashes,
            )
            if (
                migrated_hashes != installed.tool_schema_hashes
                or installed.tool_schema_hashes_legacy
            ):
                candidate[installed.name] = installed.model_copy(
                    update={
                        "tool_schema_hashes": migrated_hashes,
                        "tool_schema_hashes_legacy": False,
                    }
                )
                inventory_migrated = True
        if inventory_migrated:
            try:
                self._persist_inventory_snapshot(candidate)
            except AtomicWriteError as exc:
                if exc.publication_may_have_committed:
                    return
                logger.warning(
                    "Could not durably migrate legacy skill tool metadata; using the "
                    "compatible durable metadata for this process",
                )
            else:
                self._inventory = candidate
        for original, bundle in registration_bundles:
            installed = self._inventory.get(original.name, original)
            self._register_skill_tools(
                bundle.manifest,
                expected_hashes=installed.tool_schema_hashes,
                registration_source="inventory_reload",
            )

    def _register_skill_tools(
        self,
        manifest: Any,
        *,
        expected_hashes: dict[str, str] | None = None,
        registration_source: str = "",
    ) -> list[ToolName]:
        if self._tool_registry is None:
            return []
        required_caps = _skill_tool_capabilities(manifest)
        registered: list[ToolName] = []
        for declared_tool in getattr(manifest, "tools", []):
            tool_name = ToolName(f"skill.{manifest.name}.{declared_tool.name}")
            tool_def = ToolDefinition(
                name=tool_name,
                description=declared_tool.description,
                parameters=list(declared_tool.parameters),
                capabilities_required=sorted(required_caps, key=str),
                destinations=list(declared_tool.destinations),
                require_confirmation=bool(declared_tool.require_confirmation),
                registration_source="skill",
                registration_source_id=str(manifest.name),
                upstream_tool_name=str(declared_tool.name),
            )
            expected_hash = str((expected_hashes or {}).get(declared_tool.name, "")).strip()
            actual_hash = tool_def.schema_hash()
            if registration_source == "inventory_reload" and not expected_hash:
                self._record_registration_drop(
                    manifest=manifest,
                    tool_name=tool_name,
                    registration_source=registration_source,
                    expected_hash=expected_hash,
                    actual_hash=actual_hash,
                )
                continue
            if expected_hash and expected_hash != actual_hash:
                legacy_hash = tool_def.legacy_schema_hash_without_retry_metadata()
                if (
                    registration_source == "inventory_reload"
                    and tool_def.retry_class is ToolRetryClass.UNKNOWN
                    and expected_hash == legacy_hash
                ):
                    expected_hash = actual_hash
                else:
                    self._record_registration_drop(
                        manifest=manifest,
                        tool_name=tool_name,
                        registration_source=registration_source,
                        expected_hash=expected_hash,
                        actual_hash=actual_hash,
                    )
                    continue
            try:
                self._tool_registry.register(
                    tool_def,
                    expected_hash=expected_hash or None,
                )
            except ValueError:
                continue
            registered.append(tool_name)
        self._skill_tool_map[manifest.name] = registered
        return registered

    def _unregister_skill_tools(self, skill_name: str) -> None:
        if self._tool_registry is None:
            return
        for tool_name in self._skill_tool_map.get(skill_name, []):
            self._tool_registry.unregister(tool_name)
        self._skill_tool_map.pop(skill_name, None)

    def _unregister_all_skill_tools(self) -> None:
        for skill_name in list(self._skill_tool_map):
            self._unregister_skill_tools(skill_name)

    def _record_registration_drop(
        self,
        *,
        manifest: Any,
        tool_name: ToolName,
        registration_source: str,
        expected_hash: str,
        actual_hash: str,
    ) -> None:
        event = SkillToolRegistrationDropped(
            actor="skill_manager",
            skill_name=str(getattr(manifest, "name", "")),
            version=str(getattr(manifest, "version", "")),
            tool_name=tool_name,
            reason_code="skill:tool_schema_drift",
            registration_source=registration_source or "registration",
            expected_hash_prefix=_hash_prefix(expected_hash),
            actual_hash_prefix=_hash_prefix(actual_hash),
        )
        self._pending_registration_events.append(event)
        logger.warning(
            "Dropping reviewed skill tool during %s due to schema drift: skill=%s version=%s "
            "tool=%s expected=%s actual=%s",
            event.registration_source,
            event.skill_name,
            event.version,
            event.tool_name,
            event.expected_hash_prefix,
            event.actual_hash_prefix,
        )


def _risk_score(findings: list[Finding]) -> float:
    if not findings:
        return 0.0
    weights = {
        FindingSeverity.LOW: 0.1,
        FindingSeverity.MEDIUM: 0.35,
        FindingSeverity.HIGH: 0.7,
        FindingSeverity.CRITICAL: 1.0,
    }
    return max(weights.get(finding.severity, 0.0) for finding in findings)


def _max_severity(findings: list[Finding]) -> FindingSeverity:
    order = [
        FindingSeverity.LOW,
        FindingSeverity.MEDIUM,
        FindingSeverity.HIGH,
        FindingSeverity.CRITICAL,
    ]
    found = {finding.severity for finding in findings}
    for severity in reversed(order):
        if severity in found:
            return severity
    return FindingSeverity.LOW


def _skill_tool_capabilities(manifest: Any) -> set[Capability]:
    capabilities: set[Capability] = set()
    if getattr(manifest.capabilities, "network", []):
        capabilities.add(Capability.HTTP_REQUEST)
    filesystem_caps = list(getattr(manifest.capabilities, "filesystem", []))
    if filesystem_caps:
        capabilities.add(Capability.FILE_READ)
    if any(getattr(item, "access", "") == "read-write" for item in filesystem_caps):
        capabilities.add(Capability.FILE_WRITE)
    if getattr(manifest.capabilities, "shell", []):
        capabilities.add(Capability.SHELL_EXEC)
    return capabilities


def _declared_tool_schema_hashes(manifest: Any) -> dict[str, str]:
    required_caps = _skill_tool_capabilities(manifest)
    hashes: dict[str, str] = {}
    for declared_tool in getattr(manifest, "tools", []):
        tool_def = ToolDefinition(
            name=ToolName(f"skill.{manifest.name}.{declared_tool.name}"),
            description=declared_tool.description,
            parameters=list(declared_tool.parameters),
            capabilities_required=sorted(required_caps, key=str),
            destinations=list(declared_tool.destinations),
            require_confirmation=bool(declared_tool.require_confirmation),
            registration_source="skill",
            registration_source_id=str(manifest.name),
            upstream_tool_name=str(declared_tool.name),
        )
        hashes[declared_tool.name] = tool_def.schema_hash()
    return hashes


def _migrated_tool_schema_hashes(
    manifest: Any,
    *,
    expected_hashes: dict[str, str],
) -> dict[str, str]:
    """Upgrade only the bounded pre-retry-metadata schema representation."""

    migrated = dict(expected_hashes)
    required_caps = _skill_tool_capabilities(manifest)
    for declared_tool in getattr(manifest, "tools", []):
        expected_hash = str(expected_hashes.get(declared_tool.name, "")).strip()
        if not expected_hash:
            continue
        tool_def = ToolDefinition(
            name=ToolName(f"skill.{manifest.name}.{declared_tool.name}"),
            description=declared_tool.description,
            parameters=list(declared_tool.parameters),
            capabilities_required=sorted(required_caps, key=str),
            destinations=list(declared_tool.destinations),
            require_confirmation=bool(declared_tool.require_confirmation),
            registration_source="skill",
            registration_source_id=str(manifest.name),
            upstream_tool_name=str(declared_tool.name),
        )
        if (
            tool_def.retry_class is ToolRetryClass.UNKNOWN
            and expected_hash == tool_def.legacy_schema_hash_without_retry_metadata()
        ):
            migrated[declared_tool.name] = tool_def.schema_hash()
    return migrated


def _tool_schema_bindings_complete(
    manifest: Any,
    *,
    expected_hashes: dict[str, str],
) -> bool:
    declared_names = {
        str(declared_tool.name) for declared_tool in getattr(manifest, "tools", [])
    }
    if set(expected_hashes) != declared_names:
        return False
    return all(str(value).strip() for value in expected_hashes.values())


def _hash_prefix(value: str) -> str:
    return value[:12]
