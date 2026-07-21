"""Skill installation manager with disclosure, vetting, and lifecycle gates."""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, ValidationError

from shisad.core.atomic_state import (
    AtomicWriteError,
    StateLoadStatus,
    StatePersistenceDegradedError,
    load_state,
    write_state,
)
from shisad.core.events import SkillToolRegistrationDropped
from shisad.core.storage_platform import StorageCapability
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


class SkillInstallDecision(BaseModel):
    allowed: bool
    status: str
    reason: str = ""
    findings: list[Finding] = Field(default_factory=list)
    summary: str = ""
    artifact_state: ArtifactState = ArtifactState.DRAFT


class InstalledSkill(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    version: str
    path: str
    manifest_hash: str
    state: ArtifactState
    author: str
    tool_schema_hashes: dict[str, str] = Field(default_factory=dict)
    bundle_digest: str


class _LegacyInstalledSkill(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    version: str
    path: str
    manifest_hash: str
    state: ArtifactState
    author: str
    tool_schema_hashes: dict[str, str]


def _inventory_entries(value: list[InstalledSkill]) -> dict[str, InstalledSkill]:
    entries = {entry.name: entry for entry in value}
    if len(entries) != len(value):
        raise ValueError("skill inventory contains duplicate names")
    return entries


def _legacy_inventory(raw: bytes) -> list[InstalledSkill]:
    legacy = TypeAdapter(list[_LegacyInstalledSkill]).validate_json(raw)
    entries = [
        InstalledSkill.model_validate({**entry.model_dump(mode="json"), "bundle_digest": ""})
        for entry in legacy
    ]
    _inventory_entries(entries)
    return entries


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
        self._dangerous = DangerousPatternAnalyzer()
        self._tool_surface = ToolSurfaceAnalyzer()
        self._capability = CapabilityInferenceAnalyzer()
        self._obfuscation = ObfuscationAnalyzer()
        self._meta = MetaAnalyzer()
        self._runtime_sandbox = SkillRuntimeSandbox(
            skills_root=self._storage_dir.parent / "skills",
            config_root=self._storage_dir.parent,
        )
        self._state_status = StateLoadStatus.MISSING
        self._state_reason = ""
        self._storage_capability = StorageCapability()
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
        self._require_inventory("list_installed")
        return sorted(self._inventory.values(), key=lambda item: item.name)

    def revoke(self, *, skill_name: str, reason: str = "") -> InstalledSkill | None:
        self._require_inventory("revoke")
        installed = self._inventory.get(skill_name)
        if installed is None:
            return None
        if installed.state == ArtifactState.REVOKED:
            return installed
        updated = installed.model_copy(update={"state": ArtifactState.REVOKED})
        candidate = dict(self._inventory)
        candidate[skill_name] = updated
        self._publish_inventory(candidate, transition="revoke")
        self._unregister_skill_tools(skill_name)
        _ = reason
        return updated

    def activate_bundle(
        self,
        skill_path: Path,
        *,
        state: ArtifactState = ArtifactState.PUBLISHED,
    ) -> InstalledSkill | None:
        self._require_inventory("activate_bundle")
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
            bundle_digest=_bundle_digest(bundle),
        )
        candidate = dict(self._inventory)
        candidate[bundle.manifest.name] = installed
        self._publish_inventory(candidate, transition="activate_bundle")
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
        self._require_inventory("authorize_runtime")
        installed = self._inventory.get(skill_name)
        if installed is None:
            return SkillSandboxDecision(allowed=False, reason="unknown_skill")
        if installed.state != ArtifactState.PUBLISHED:
            return SkillSandboxDecision(allowed=False, reason="skill_not_published")
        path = Path(installed.path)
        if not path.exists():
            return SkillSandboxDecision(allowed=False, reason="skill_path_missing")
        try:
            bundle = load_skill_bundle(
                path,
                allowed_dependency_sources=set(self._policy.dependency_source_allowlist),
            )
        except (FileNotFoundError, OSError, TypeError, ValueError):
            return SkillSandboxDecision(allowed=False, reason="skill_bundle_drift")
        bundle_digest = _bundle_digest(bundle)
        if not installed.bundle_digest:
            return SkillSandboxDecision(allowed=False, reason="skill_bundle_drift")
        manifest_hash = bundle.manifest.manifest_hash()
        if manifest_hash != installed.manifest_hash:
            return SkillSandboxDecision(allowed=False, reason="skill_manifest_drift")
        current_tool_hashes = _declared_tool_schema_hashes(bundle.manifest)
        if current_tool_hashes != dict(installed.tool_schema_hashes):
            return SkillSandboxDecision(allowed=False, reason="skill_tool_schema_drift")
        if bundle_digest != installed.bundle_digest:
            return SkillSandboxDecision(allowed=False, reason="skill_bundle_drift")
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

    def _require_inventory(self, transition: str) -> None:
        if self._state_status in {StateLoadStatus.MISSING, StateLoadStatus.OK}:
            return
        raise StatePersistenceDegradedError(
            authority="skills",
            transition=transition,
            stage="state_load",
            reason=self._state_reason or "restore known-good skill inventory",
        )

    def state_health(self) -> dict[str, str]:
        status = {
            StateLoadStatus.MISSING: "missing",
            StateLoadStatus.OK: "ok",
            StateLoadStatus.CORRUPT: "corrupt",
            StateLoadStatus.UNSUPPORTED_SCHEMA: "unsupported",
        }[self._state_status]
        return {
            "component": "skills",
            "status": status,
            "reason": self._state_reason,
            "durability": self._storage_capability.parent_sync,
            "permissions": self._storage_capability.permissions,
            "remains_usable": "conversation, built-in tools, and static skill review",
        }

    def _load_inventory(self) -> dict[str, InstalledSkill]:
        result = load_state(
            self._inventory_path,
            list[InstalledSkill],
            legacy_decoder=_legacy_inventory,
        )
        self._state_status = result.status
        if result.status is not StateLoadStatus.OK or result.value is None:
            if result.status not in {StateLoadStatus.MISSING, StateLoadStatus.OK}:
                self._state_reason = (
                    "skill inventory is invalid; restore a known-good inventory snapshot"
                )
            return {}
        try:
            return _inventory_entries(result.value)
        except ValueError:
            self._state_status = StateLoadStatus.CORRUPT
            self._state_reason = "skill inventory contains conflicting entries"
            return {}

    def _publish_inventory(self, candidate: dict[str, InstalledSkill], *, transition: str) -> None:
        payload = [
            entry.model_dump(mode="json")
            for entry in sorted(candidate.values(), key=lambda x: x.name)
        ]
        try:
            self._storage_capability = write_state(self._inventory_path, payload)
        except (AtomicWriteError, OSError, TypeError, ValueError, ValidationError) as exc:
            self._state_status = StateLoadStatus.CORRUPT
            self._state_reason = "skill inventory publication failed; restore known-good state"
            raise StatePersistenceDegradedError(
                authority="skills",
                transition=transition,
                stage=str(getattr(exc, "stage", "encode")),
                reason=self._state_reason,
            ) from exc
        self._inventory = {name: entry.model_copy(deep=True) for name, entry in candidate.items()}
        self._state_status = StateLoadStatus.OK
        self._state_reason = ""

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
        if self._state_status not in {
            StateLoadStatus.MISSING,
            StateLoadStatus.OK,
        }:
            return
        bundles: dict[str, SkillBundle] = {}
        candidate = dict(self._inventory)
        inventory_migrated = False
        for installed in self._inventory.values():
            if installed.state != ArtifactState.PUBLISHED:
                continue
            path = Path(installed.path)
            if not path.exists():
                self._record_unavailable_bundle(installed, "skill:path_missing")
                continue
            try:
                bundle = load_skill_bundle(
                    path,
                    allowed_dependency_sources=set(self._policy.dependency_source_allowlist),
                )
            except (FileNotFoundError, OSError, TypeError, ValueError):
                self._record_unavailable_bundle(installed, "skill:bundle_unloadable")
                continue
            bundles[installed.name] = bundle
            digest = _bundle_digest(bundle)
            expected_hashes = _migrate_legacy_tool_hashes(
                bundle.manifest, dict(installed.tool_schema_hashes)
            )
            hashes_migrated = expected_hashes != installed.tool_schema_hashes
            if (
                not installed.bundle_digest
                and bundle.manifest.manifest_hash() == installed.manifest_hash
            ) or (digest == installed.bundle_digest and hashes_migrated):
                candidate[installed.name] = installed.model_copy(
                    update={"bundle_digest": digest, "tool_schema_hashes": expected_hashes},
                    deep=True,
                )
                inventory_migrated = True
        if inventory_migrated:
            try:
                self._publish_inventory(candidate, transition="legacy_migration")
            except StatePersistenceDegradedError:
                return
        if self._tool_registry is None:
            return
        for installed in self._inventory.values():
            if installed.state != ArtifactState.PUBLISHED:
                continue
            loaded_bundle = bundles.get(installed.name)
            if loaded_bundle is None:
                continue
            if _bundle_digest(loaded_bundle) != installed.bundle_digest:
                self._record_bundle_drift(installed, loaded_bundle)
                continue
            self._register_skill_tools(
                loaded_bundle.manifest,
                expected_hashes=dict(installed.tool_schema_hashes),
                registration_source="inventory_reload",
            )

    def _record_bundle_drift(self, installed: InstalledSkill, bundle: SkillBundle) -> None:
        actual_hashes = _declared_tool_schema_hashes(bundle.manifest)
        actual_digest = _bundle_digest(bundle)
        for name in sorted(set(installed.tool_schema_hashes) | set(actual_hashes)):
            expected_hash = installed.tool_schema_hashes.get(name, "")
            actual_hash = actual_hashes.get(name, "")
            schema_drift = bool(expected_hash and expected_hash != actual_hash)
            self._record_registration_drop(
                manifest=bundle.manifest,
                tool_name=ToolName(f"skill.{installed.name}.{name}"),
                registration_source="inventory_reload",
                expected_hash=expected_hash if schema_drift else installed.bundle_digest,
                actual_hash=actual_hash if schema_drift else actual_digest,
                reason_code="skill:tool_schema_drift" if schema_drift else "skill:bundle_drift",
            )

    def _record_unavailable_bundle(self, installed: InstalledSkill, reason_code: str) -> None:
        self._record_registration_drop(
            manifest=installed,
            tool_name=ToolName(f"skill.{installed.name}.__bundle__"),
            registration_source="inventory_reload",
            expected_hash=installed.bundle_digest,
            actual_hash="",
            reason_code=reason_code,
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
        registered: list[ToolName] = []
        for declared_tool in getattr(manifest, "tools", []):
            tool_name = ToolName(f"skill.{manifest.name}.{declared_tool.name}")
            tool_def = _tool_definition(manifest, declared_tool)
            expected_hash = str((expected_hashes or {}).get(declared_tool.name, "")).strip()
            actual_hash = tool_def.schema_hash()
            if expected_hash and expected_hash != actual_hash:
                legacy_hash = tool_def.legacy_schema_hash_without_retry_metadata()
                if (
                    registration_source == "inventory_reload"
                    and tool_def.retry_class is ToolRetryClass.UNKNOWN
                    and expected_hash == legacy_hash
                    and expected_hashes is not None
                ):
                    expected_hashes[declared_tool.name] = actual_hash
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

    def _record_registration_drop(
        self,
        *,
        manifest: Any,
        tool_name: ToolName,
        registration_source: str,
        expected_hash: str,
        actual_hash: str,
        reason_code: str = "skill:tool_schema_drift",
    ) -> None:
        event = SkillToolRegistrationDropped(
            actor="skill_manager",
            skill_name=str(getattr(manifest, "name", "")),
            version=str(getattr(manifest, "version", "")),
            tool_name=tool_name,
            reason_code=reason_code,
            registration_source=registration_source or "registration",
            expected_hash_prefix=_hash_prefix(expected_hash),
            actual_hash_prefix=_hash_prefix(actual_hash),
        )
        self._pending_registration_events.append(event)
        drift_label = "schema drift" if reason_code == "skill:tool_schema_drift" else "bundle drift"
        logger.warning(
            "Dropping reviewed skill tool during %s due to %s: skill=%s version=%s "
            "tool=%s expected=%s actual=%s",
            event.registration_source,
            drift_label,
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


def _tool_definition(manifest: Any, declared_tool: Any) -> ToolDefinition:
    return ToolDefinition(
        name=ToolName(f"skill.{manifest.name}.{declared_tool.name}"),
        description=declared_tool.description,
        parameters=list(declared_tool.parameters),
        capabilities_required=sorted(_skill_tool_capabilities(manifest), key=str),
        destinations=list(declared_tool.destinations),
        require_confirmation=bool(declared_tool.require_confirmation),
        registration_source="skill",
        registration_source_id=str(manifest.name),
        upstream_tool_name=str(declared_tool.name),
        sandbox_type="nsjail",
    )


def _declared_tool_schema_hashes(manifest: Any) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for declared_tool in getattr(manifest, "tools", []):
        hashes[declared_tool.name] = _tool_definition(manifest, declared_tool).schema_hash()
    return hashes


def _migrate_legacy_tool_hashes(manifest: Any, expected: dict[str, str]) -> dict[str, str]:
    migrated = dict(expected)
    for declared_tool in getattr(manifest, "tools", []):
        tool_def = _tool_definition(manifest, declared_tool)
        stored = expected.get(declared_tool.name, "")
        if (
            tool_def.retry_class is ToolRetryClass.UNKNOWN
            and stored == tool_def.legacy_schema_hash_without_retry_metadata()
        ):
            migrated[declared_tool.name] = tool_def.schema_hash()
    return migrated


def _bundle_digest(bundle: SkillBundle) -> str:
    payload = {
        "manifest": bundle.manifest.model_dump(mode="json"),
        "files": sorted((item.path, item.sha256) for item in bundle.files),
    }
    canonical = json.dumps(
        payload,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _hash_prefix(value: str) -> str:
    return value[:12]
