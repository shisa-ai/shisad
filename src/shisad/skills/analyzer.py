"""Static analyzer primitives for skill bundles."""

from __future__ import annotations

import hashlib
import math
import re
from collections.abc import Iterable
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlparse

from pydantic import BaseModel, Field

from shisad.core.host_matching import host_matches
from shisad.core.types import ThreatCategory
from shisad.security.firewall.classifier import PatternInjectionClassifier
from shisad.skills.manifest import SkillManifest, parse_manifest

_URL_RE = re.compile(r"https?://[^\s)>\]\"']+")
_HTTP_RE = re.compile(r"\b(?:curl|wget|nc|ncat|telnet|ssh|scp)\b", re.IGNORECASE)
_SHELL_EXEC_RE = re.compile(r"\b(?:bash\s+-c|sh\s+-c|eval|exec)\b", re.IGNORECASE)
_ENCODING_RE = re.compile(r"\b(?:base64|xxd|od)\b", re.IGNORECASE)
_ENV_SENSITIVE_RE = re.compile(r"\$(?:HOME|AWS_[A-Z_]+|GOOGLE_[A-Z_]+)", re.IGNORECASE)
_DNS_EXFIL_RE = re.compile(r"\b(?:nslookup|dig|host)\b", re.IGNORECASE)
_FILE_READ_RE = re.compile(r"(~\/\.ssh|~\/\.aws|\/etc\/passwd|credentials)", re.IGNORECASE)
_DOWNLOAD_TOOL_RE = re.compile(r"\b(?:curl|wget)\b", re.IGNORECASE)
_SCRIPT_EXEC_RE = re.compile(r"\b(?:bash|sh|python)\b", re.IGNORECASE)
_CLICKFIX_RE = re.compile(
    r"(install prerequisite|security update|required patch|click here to fix)",
    re.IGNORECASE,
)
_BINARY_FETCH_RE = re.compile(r"\.(?:bin|exe|dmg|pkg|msi)\b", re.IGNORECASE)
_COMMAND_RE = re.compile(r"`([^`]+)`")
_SHELL_FRAGMENT_RE = re.compile(
    r"\b(?:curl|wget|nc|ncat|telnet|ssh|scp)\b(?:\s+[^;&|`]+)?",
    re.IGNORECASE,
)
_INVISIBLE_RE = re.compile(r"[\u200b-\u200f\u2060\ufeff]")
_HOMOGLYPH_CHAR_RE = re.compile(r"[\u0400-\u04FF\u0391-\u03A9\u03B1-\u03C9]")
_HIGH_ENTROPY_RE = re.compile(r"[A-Za-z0-9+/=]{48,}")
_MAX_BUNDLE_FILE_BYTES = 8 * 1024 * 1024


class FindingSeverity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Finding(BaseModel):
    """A single analyzer finding."""

    analyzer: str
    category: ThreatCategory
    severity: FindingSeverity
    title: str
    detail: str
    file_path: str = ""
    line: int = 0
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    false_positive: bool = False


class SkillFile(BaseModel):
    path: str
    size: int
    binary: bool = False
    content: str = ""
    sha256: str
    external_refs: list[str] = Field(default_factory=list)


class SkillBundle(BaseModel):
    root_dir: str
    manifest_path: str
    manifest: SkillManifest
    files: list[SkillFile] = Field(default_factory=list)


class BaseAnalyzer(Protocol):
    """Analyzer interface."""

    def analyze(self, skill: SkillBundle) -> list[Finding]: ...


class CapabilityInferenceResult(BaseModel):
    network_domains: set[str] = Field(default_factory=set)
    file_paths: set[str] = Field(default_factory=set)
    shell_commands: set[str] = Field(default_factory=set)
    environment_vars: set[str] = Field(default_factory=set)


def load_skill_bundle(
    root: Path,
    *,
    allowed_dependency_sources: set[str] | None = None,
) -> SkillBundle:
    manifest_path = root / "skill.manifest.yaml"
    manifest = parse_manifest(
        manifest_path,
        allowed_dependency_sources=allowed_dependency_sources,
    )
    files: list[SkillFile] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if path.name == "skill.manifest.yaml":
            continue
        raw = path.read_bytes()
        if len(raw) > _MAX_BUNDLE_FILE_BYTES:
            raise ValueError(
                "Skill file too large for analysis: "
                f"{path} ({len(raw)} bytes > {_MAX_BUNDLE_FILE_BYTES})"
            )
        sha256 = hashlib.sha256(raw).hexdigest()
        binary = b"\x00" in raw
        content = "" if binary else raw.decode("utf-8", errors="ignore")
        refs = _URL_RE.findall(content) if content else []
        files.append(
            SkillFile(
                path=str(path.relative_to(root)),
                size=len(raw),
                binary=binary,
                content=content,
                sha256=sha256,
                external_refs=sorted(set(refs)),
            )
        )
    return SkillBundle(
        root_dir=str(root),
        manifest_path=str(manifest_path),
        manifest=manifest,
        files=files,
    )


class DangerousPatternAnalyzer:
    """Static pattern scanner with optional YARA-derived matching."""

    def __init__(self, *, yara_rules_dir: Path | None = None) -> None:
        self._classifier = PatternInjectionClassifier(yara_rules_dir=yara_rules_dir)

    @staticmethod
    def _scan_regex_patterns(path: str, content: str) -> list[Finding]:
        """Compatibility shim for older callers/tests using the pattern-only scanner."""
        return ToolSurfaceAnalyzer._scan_regex_patterns(path, content)

    def analyze(self, skill: SkillBundle) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(_scan_typosquatting(skill))
        for file in skill.files:
            if file.binary:
                findings.append(
                    Finding(
                        analyzer="dangerous-pattern",
                        category=ThreatCategory.SUPPLY_CHAIN,
                        severity=FindingSeverity.MEDIUM,
                        title="Binary file in skill bundle",
                        detail="Non-text files are blocked from automatic install review.",
                        file_path=file.path,
                        tags=["binary"],
                    )
                )
                continue

            content = file.content
            findings.extend(_scan_executable_payload(path=file.path, content=content))
            findings.extend(self._scan_regex_patterns(file.path, content))
            findings.extend(_scan_delivery_chain(path=file.path, content=content))
            cls = self._classifier.classify(content)
            if cls.risk_score >= 0.2:
                findings.append(
                    Finding(
                        analyzer="dangerous-pattern",
                        category=ThreatCategory.PROMPT_INJECTION_INDIRECT,
                        severity=(
                            FindingSeverity.HIGH
                            if cls.risk_score >= 0.45
                            else FindingSeverity.MEDIUM
                        ),
                        title="Potential prompt-injection payload",
                        detail=", ".join(cls.risk_factors) or "Suspicious instruction payload",
                        file_path=file.path,
                        tags=["yara", "pattern"],
                        metadata={
                            "risk_score": cls.risk_score,
                            "risk_factors": cls.risk_factors,
                            "matched_patterns": cls.matched_patterns,
                        },
                    )
                )
        return findings


class ToolSurfaceAnalyzer:
    """Scanner/validator for skill-declared tool metadata."""

    def __init__(self, *, yara_rules_dir: Path | None = None) -> None:
        self._classifier = PatternInjectionClassifier(yara_rules_dir=yara_rules_dir)

    def analyze(self, skill: SkillBundle) -> list[Finding]:
        findings: list[Finding] = []
        declared_domains = {
            item.domain.strip().lower()
            for item in skill.manifest.capabilities.network
            if item.domain.strip()
        }
        for declared_tool in skill.manifest.tools:
            metadata_blob = "\n".join(
                piece
                for piece in [
                    declared_tool.description,
                    *[
                        str(getattr(parameter, "description", "") or "")
                        for parameter in declared_tool.parameters
                    ],
                ]
                if piece.strip()
            )
            if metadata_blob.strip():
                cls = self._classifier.classify(metadata_blob)
                if cls.risk_score >= 0.2:
                    findings.append(
                        Finding(
                            analyzer="tool-surface",
                            category=ThreatCategory.PROMPT_INJECTION_INDIRECT,
                            severity=(
                                FindingSeverity.HIGH
                                if cls.risk_score >= 0.45
                                else FindingSeverity.MEDIUM
                            ),
                            title="Potential prompt-injection in tool metadata",
                            detail=", ".join(cls.risk_factors) or "Suspicious tool metadata",
                            file_path="skill.manifest.yaml",
                            tags=["tool_surface", "metadata_injection"],
                            metadata={
                                "tool_name": declared_tool.name,
                                "risk_score": cls.risk_score,
                                "risk_factors": cls.risk_factors,
                            },
                        )
                    )
            for destination in declared_tool.destinations:
                normalized = destination.strip()
                host = (urlparse(normalized).hostname or normalized).lower()
                if not host:
                    continue
                if declared_domains and any(host_matches(host, rule) for rule in declared_domains):
                    continue
                findings.append(
                    Finding(
                        analyzer="tool-surface",
                        category=ThreatCategory.SUPPLY_CHAIN,
                        severity=FindingSeverity.HIGH,
                        title="Tool destination exceeds declared network capability",
                        detail=(
                            f"Tool '{declared_tool.name}' declares destination '{destination}' "
                            "outside the manifest network capability set."
                        ),
                        file_path="skill.manifest.yaml",
                        tags=["tool_surface", "tool_surface_policy", "destination_scope"],
                        metadata={
                            "tool_name": declared_tool.name,
                            "destination": destination,
                            "declared_domains": sorted(declared_domains),
                        },
                    )
                )
        return findings

    @staticmethod
    def _scan_regex_patterns(path: str, content: str) -> list[Finding]:
        findings: list[Finding] = []
        for line_number, line in enumerate(content.splitlines(), start=1):
            lowered = line.lower()
            if _HTTP_RE.search(line):
                findings.append(
                    Finding(
                        analyzer="dangerous-pattern",
                        category=ThreatCategory.DATA_EXFILTRATION,
                        severity=FindingSeverity.HIGH,
                        title="Network utility invocation",
                        detail=line.strip()[:240],
                        file_path=path,
                        line=line_number,
                        tags=["network_tool"],
                    )
                )
            if _SHELL_EXEC_RE.search(line):
                findings.append(
                    Finding(
                        analyzer="dangerous-pattern",
                        category=ThreatCategory.PRIVILEGE_ESCALATION,
                        severity=FindingSeverity.HIGH,
                        title="Shell execution primitive",
                        detail=line.strip()[:240],
                        file_path=path,
                        line=line_number,
                        tags=["shell_exec"],
                    )
                )
            if _ENCODING_RE.search(line):
                findings.append(
                    Finding(
                        analyzer="dangerous-pattern",
                        category=ThreatCategory.TOOL_POISONING,
                        severity=FindingSeverity.MEDIUM,
                        title="Encoding utility usage",
                        detail=line.strip()[:240],
                        file_path=path,
                        line=line_number,
                        tags=["encoding"],
                    )
                )
            if _ENV_SENSITIVE_RE.search(line):
                findings.append(
                    Finding(
                        analyzer="dangerous-pattern",
                        category=ThreatCategory.DATA_EXFILTRATION,
                        severity=FindingSeverity.HIGH,
                        title="Sensitive environment variable access",
                        detail=line.strip()[:240],
                        file_path=path,
                        line=line_number,
                        tags=["env_access"],
                    )
                )
            for url in _URL_RE.findall(line):
                if url.lower().startswith("http://"):
                    findings.append(
                        Finding(
                            analyzer="dangerous-pattern",
                            category=ThreatCategory.DATA_EXFILTRATION,
                            severity=FindingSeverity.MEDIUM,
                            title="Non-HTTPS external URL",
                            detail=url,
                            file_path=path,
                            line=line_number,
                            tags=["url", "non_https"],
                        )
                    )
            if "xattr -d com.apple.quarantine" in lowered or "spctl --master-disable" in lowered:
                findings.append(
                    Finding(
                        analyzer="dangerous-pattern",
                        category=ThreatCategory.PRIVILEGE_ESCALATION,
                        severity=FindingSeverity.CRITICAL,
                        title="Gatekeeper bypass command",
                        detail=line.strip()[:240],
                        file_path=path,
                        line=line_number,
                        tags=["gatekeeper_bypass"],
                    )
                )
        return findings


class CapabilityInferenceAnalyzer:
    """Infer required capabilities from all skill files and compare to manifest."""

    def infer(self, skill: SkillBundle) -> CapabilityInferenceResult:
        result = CapabilityInferenceResult()
        for file in skill.files:
            if file.binary:
                continue
            for url in _URL_RE.findall(file.content):
                host = re.sub(r"^https?://", "", url, flags=re.IGNORECASE).split("/", 1)[0]
                if host:
                    result.network_domains.add(host.lower())
            for line in file.content.splitlines():
                if _HTTP_RE.search(line) or _DNS_EXFIL_RE.search(line):
                    for fragment in _extract_shell_fragments(line):
                        result.shell_commands.add(fragment)
                if _FILE_READ_RE.search(line):
                    result.file_paths.add(line.strip())
                for env_match in _ENV_SENSITIVE_RE.findall(line):
                    result.environment_vars.add(env_match.upper().lstrip("$"))
                for command in _COMMAND_RE.findall(line):
                    if command.strip():
                        result.shell_commands.add(_normalize_command(command))
        return result

    def analyze(self, skill: SkillBundle) -> list[Finding]:
        inferred = self.infer(skill)
        declared_domains = {item.domain.lower() for item in skill.manifest.capabilities.network}
        undeclared_domains = sorted(
            domain for domain in inferred.network_domains if domain not in declared_domains
        )

        declared_env = {item.var.upper() for item in skill.manifest.capabilities.environment}
        undeclared_env = sorted(
            item for item in inferred.environment_vars if item not in declared_env
        )

        declared_shell = {
            _normalize_command(item.command) for item in skill.manifest.capabilities.shell
        }
        undeclared_shell = sorted(
            item
            for item in inferred.shell_commands
            if declared_shell
            and not any(_shell_command_matches(item, declared) for declared in declared_shell)
        )

        findings: list[Finding] = []
        if undeclared_domains:
            findings.append(
                Finding(
                    analyzer="capability-inference",
                    category=ThreatCategory.DATA_EXFILTRATION,
                    severity=FindingSeverity.CRITICAL,
                    title="Undeclared network capability",
                    detail=", ".join(undeclared_domains),
                    tags=["undeclared_network"],
                )
            )
        if undeclared_env:
            findings.append(
                Finding(
                    analyzer="capability-inference",
                    category=ThreatCategory.DATA_EXFILTRATION,
                    severity=FindingSeverity.HIGH,
                    title="Undeclared environment access",
                    detail=", ".join(undeclared_env),
                    tags=["undeclared_env"],
                )
            )
        if undeclared_shell:
            findings.append(
                Finding(
                    analyzer="capability-inference",
                    category=ThreatCategory.PRIVILEGE_ESCALATION,
                    severity=FindingSeverity.HIGH,
                    title="Undeclared shell behavior",
                    detail=", ".join(undeclared_shell[:3]),
                    tags=["undeclared_shell"],
                )
            )
        return findings


class ObfuscationAnalyzer:
    """Detect obfuscation indicators in text content."""

    def analyze(self, skill: SkillBundle) -> list[Finding]:
        findings: list[Finding] = []
        for file in skill.files:
            if file.binary:
                continue
            for line_number, line in enumerate(file.content.splitlines(), start=1):
                if _INVISIBLE_RE.search(line):
                    findings.append(
                        Finding(
                            analyzer="obfuscation",
                            category=ThreatCategory.TOOL_POISONING,
                            severity=FindingSeverity.HIGH,
                            title="Invisible unicode character detected",
                            detail=line.strip()[:240],
                            file_path=file.path,
                            line=line_number,
                            tags=["unicode_invisible"],
                        )
                    )
                if _has_suspicious_mixed_script_token(line):
                    findings.append(
                        Finding(
                            analyzer="obfuscation",
                            category=ThreatCategory.MASQUERADING,
                            severity=FindingSeverity.MEDIUM,
                            title="Potential homoglyph usage",
                            detail=line.strip()[:240],
                            file_path=file.path,
                            line=line_number,
                            tags=["homoglyph"],
                        )
                    )
                for token in _HIGH_ENTROPY_RE.findall(line):
                    if _entropy(token) >= 4.0:
                        findings.append(
                            Finding(
                                analyzer="obfuscation",
                                category=ThreatCategory.TOOL_POISONING,
                                severity=FindingSeverity.HIGH,
                                title="High-entropy payload candidate",
                                detail=token[:96],
                                file_path=file.path,
                                line=line_number,
                                tags=["high_entropy"],
                                metadata={"entropy": round(_entropy(token), 4)},
                            )
                        )
                        break
        return findings


def aggregate_findings(*finding_sets: Iterable[Finding]) -> list[Finding]:
    merged: list[Finding] = []
    for finding_set in finding_sets:
        merged.extend(list(finding_set))
    return merged


def _entropy(value: str) -> float:
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    total = len(value)
    if total == 0:
        return 0.0
    score = 0.0
    for count in counts.values():
        p = count / total
        score -= p * math.log2(p)
    return score


def _scan_delivery_chain(*, path: str, content: str) -> list[Finding]:
    has_url = bool(_URL_RE.search(content))
    has_download = bool(_DOWNLOAD_TOOL_RE.search(content))
    has_script_exec = bool(_SCRIPT_EXEC_RE.search(content))
    has_pipe_exec = bool(re.search(r"\|\s*(?:bash|sh)\b", content, re.IGNORECASE))
    has_binary_fetch = bool(_BINARY_FETCH_RE.search(content))

    findings: list[Finding] = []
    if _CLICKFIX_RE.search(content) and has_url:
        findings.append(
            Finding(
                analyzer="dangerous-pattern",
                category=ThreatCategory.SUPPLY_CHAIN,
                severity=FindingSeverity.HIGH,
                title="ClickFix-style staged delivery prompt",
                detail=path,
                file_path=path,
                tags=["staged_delivery", "clickfix"],
            )
        )
    if has_url and has_download and (has_pipe_exec or has_script_exec):
        findings.append(
            Finding(
                analyzer="dangerous-pattern",
                category=ThreatCategory.TOOL_POISONING,
                severity=FindingSeverity.HIGH,
                title="Staged download-and-execute chain",
                detail=path,
                file_path=path,
                tags=["staged_delivery"],
            )
        )
    if has_url and has_download and (has_pipe_exec or has_script_exec) and has_binary_fetch:
        findings.append(
            Finding(
                analyzer="dangerous-pattern",
                category=ThreatCategory.TOOL_POISONING,
                severity=FindingSeverity.CRITICAL,
                title="Multi-stage binary delivery chain",
                detail=path,
                file_path=path,
                tags=["multi_stage_delivery"],
            )
        )
    return findings


def _scan_executable_payload(*, path: str, content: str) -> list[Finding]:
    suffix = Path(path).suffix.lower()
    if suffix not in {".sh", ".py", ".bash", ".zsh"}:
        return []
    if not content.lstrip().startswith("#!"):
        return []
    return [
        Finding(
            analyzer="dangerous-pattern",
            category=ThreatCategory.SUPPLY_CHAIN,
            severity=FindingSeverity.HIGH,
            title="Executable payload file in skill bundle",
            detail=path,
            file_path=path,
            tags=["embedded_executable", "mcp_bypass"],
        )
    ]


def _scan_typosquatting(skill: SkillBundle) -> list[Finding]:
    known = {
        "calendar-manager",
        "browser-agent",
        "workspace-assistant",
        "email-summarizer",
        "retrieval-helper",
    }
    normalized = skill.manifest.name.strip().lower()
    for candidate in known:
        if normalized == candidate:
            continue
        if _levenshtein_distance(normalized, candidate) <= 2:
            return [
                Finding(
                    analyzer="dangerous-pattern",
                    category=ThreatCategory.MASQUERADING,
                    severity=FindingSeverity.HIGH,
                    title="Potential typosquatting skill name",
                    detail=f"{normalized} resembles {candidate}",
                    tags=["typosquat"],
                )
            ]
    return []


def _levenshtein_distance(left: str, right: str) -> int:
    if left == right:
        return 0
    if not left:
        return len(right)
    if not right:
        return len(left)

    previous = list(range(len(right) + 1))
    for i, left_char in enumerate(left, start=1):
        current = [i]
        for j, right_char in enumerate(right, start=1):
            insert_cost = current[j - 1] + 1
            delete_cost = previous[j] + 1
            replace_cost = previous[j - 1] + (0 if left_char == right_char else 1)
            current.append(min(insert_cost, delete_cost, replace_cost))
        previous = current
    return previous[-1]


def _normalize_command(command: str) -> str:
    return " ".join(command.strip().split())


def _extract_shell_fragments(line: str) -> list[str]:
    fragments: list[str] = []
    for match in _SHELL_FRAGMENT_RE.finditer(line):
        fragment = _normalize_command(match.group(0))
        if fragment:
            fragments.append(fragment)
    return fragments


def _shell_command_matches(inferred: str, declared: str) -> bool:
    inferred_norm = _normalize_command(inferred)
    declared_norm = _normalize_command(declared)
    if not inferred_norm or not declared_norm:
        return False
    if inferred_norm == declared_norm:
        return True
    if inferred_norm.startswith(declared_norm) or declared_norm.startswith(inferred_norm):
        return True
    inferred_head = inferred_norm.split(" ", 1)[0]
    declared_head = declared_norm.split(" ", 1)[0]
    if inferred_head != declared_head:
        return False
    inferred_urls = set(_URL_RE.findall(inferred_norm))
    declared_urls = set(_URL_RE.findall(declared_norm))
    if inferred_urls and declared_urls:
        return inferred_urls == declared_urls
    return True


def _has_suspicious_mixed_script_token(line: str) -> bool:
    for token in re.split(r"\s+", line):
        if not token:
            continue
        if not _HOMOGLYPH_CHAR_RE.search(token):
            continue
        if re.search(r"[A-Za-z]", token):
            return True
    return False
