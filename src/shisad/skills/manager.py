"""Skill installation manager with disclosure, vetting, and lifecycle gates."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from shisad.core.tools.registry import ToolRegistry
from shisad.core.tools.schema import ToolDefinition
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
        self._dangerous = DangerousPatternAnalyzer(
            yara_rules_dir=Path(__file__).resolve().parents[1] / "security" / "rules" / "yara"
        )
        self._tool_surface = ToolSurfaceAnalyzer(
            yara_rules_dir=Path(__file__).resolve().parents[1] / "security" / "rules" / "yara"
        )
        self._capability = CapabilityInferenceAnalyzer()
        self._obfuscation = ObfuscationAnalyzer()
        self._meta = MetaAnalyzer()
        self._runtime_sandbox = SkillRuntimeSandbox(
            skills_root=self._storage_dir.parent / "skills",
            config_root=self._storage_dir.parent,
        )
        self._inventory = self._load_inventory()
        self._skill_tool_map: dict[str, list[ToolName]] = {}
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
        findings.extend(
            scan_cross_skill([bundle, *self._installed_bundles()])
        )
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
        return sorted(self._inventory.values(), key=lambda item: item.name)

    def revoke(self, *, skill_name: str, reason: str = "") -> InstalledSkill | None:
        installed = self._inventory.get(skill_name)
        if installed is None:
            return None
        if installed.state == ArtifactState.REVOKED:
            return installed
        updated = installed.model_copy(update={"state": ArtifactState.REVOKED})
        self._inventory[skill_name] = updated
        self._persist_inventory()
        self._unregister_skill_tools(skill_name)
        _ = reason
        return updated

    def activate_bundle(
        self,
        skill_path: Path,
        *,
        state: ArtifactState = ArtifactState.PUBLISHED,
    ) -> InstalledSkill | None:
        bundle = load_skill_bundle(
            skill_path,
            allowed_dependency_sources=set(self._policy.dependency_source_allowlist),
        )
        self._unregister_skill_tools(bundle.manifest.name)
        installed = InstalledSkill(
            name=bundle.manifest.name,
            version=bundle.manifest.version,
            path=str(skill_path),
            manifest_hash=bundle.manifest.manifest_hash(),
            state=state,
            author=bundle.manifest.author,
            tool_schema_hashes=_declared_tool_schema_hashes(bundle.manifest),
        )
        self._inventory[bundle.manifest.name] = installed
        self._persist_inventory()
        if state == ArtifactState.PUBLISHED:
            self._register_skill_tools(
                bundle.manifest,
                expected_hashes=installed.tool_schema_hashes,
            )
        return installed

    def tool_names_for_skill(self, skill_name: str) -> list[str]:
        return [str(name) for name in self._skill_tool_map.get(skill_name, [])]

    def authorize_runtime(
        self,
        *,
        skill_name: str,
        request: SkillExecutionRequest,
    ) -> SkillSandboxDecision:
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

    def _load_inventory(self) -> dict[str, InstalledSkill]:
        if not self._inventory_path.exists():
            return {}
        payload = json.loads(self._inventory_path.read_text(encoding="utf-8"))
        if not isinstance(payload, list):
            return {}
        entries = [
            InstalledSkill.model_validate(item)
            for item in payload
            if isinstance(item, dict)
        ]
        return {entry.name: entry for entry in entries}

    def _persist_inventory(self) -> None:
        payload = [entry.model_dump(mode="json") for entry in self.list_installed()]
        self._inventory_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

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
        if self._tool_registry is None:
            return
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
            self._register_skill_tools(
                bundle.manifest,
                expected_hashes=getattr(installed, "tool_schema_hashes", {}),
            )

    def _register_skill_tools(
        self,
        manifest: Any,
        *,
        expected_hashes: dict[str, str] | None = None,
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
            )
            try:
                self._tool_registry.register(
                    tool_def,
                    expected_hash=(expected_hashes or {}).get(declared_tool.name),
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
        )
        hashes[declared_tool.name] = tool_def.schema_hash()
    return hashes
