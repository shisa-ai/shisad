"""Full-file disclosure rendering helpers for skill installation review."""

from __future__ import annotations

import difflib
from pathlib import Path

from pydantic import BaseModel, Field

from shisad.skills.analyzer import Finding, SkillBundle
from shisad.skills.signatures import VerificationResult


class FileDisclosure(BaseModel):
    path: str
    size: int
    file_type: str
    external_refs: list[str] = Field(default_factory=list)
    binary: bool = False


class DiffEntry(BaseModel):
    path: str
    added_lines: int = 0
    removed_lines: int = 0
    unified_diff: str = ""
    dangerous_additions: list[str] = Field(default_factory=list)


def list_files(skill: SkillBundle) -> list[FileDisclosure]:
    items: list[FileDisclosure] = []
    for file in skill.files:
        suffix = Path(file.path).suffix.lower()
        file_type = "binary" if file.binary else (suffix.lstrip(".") or "text")
        items.append(
            FileDisclosure(
                path=file.path,
                size=file.size,
                file_type=file_type,
                external_refs=list(file.external_refs),
                binary=file.binary,
            )
        )
    return items


def view_content(skill: SkillBundle, *, path: str) -> str:
    for file in skill.files:
        if file.path != path:
            continue
        if file.binary:
            return f"[binary file: {path}]"
        return file.content
    raise ValueError(f"Unknown file path: {path}")


def diff_versions(
    old: SkillBundle,
    new: SkillBundle,
    *,
    findings: list[Finding] | None = None,
) -> list[DiffEntry]:
    old_by_path = {file.path: file for file in old.files}
    new_by_path = {file.path: file for file in new.files}
    all_paths = sorted(set(old_by_path) | set(new_by_path))
    findings = findings or []

    entries: list[DiffEntry] = []
    for path in all_paths:
        before = old_by_path.get(path)
        after = new_by_path.get(path)
        binary_changed = bool(
            before is not None
            and after is not None
            and (before.binary or after.binary)
            and before.sha256 != after.sha256
        )
        binary_added = before is None and after is not None and after.binary
        binary_removed = before is not None and after is None and before.binary
        before_lines = [] if before is None else before.content.splitlines()
        after_lines = [] if after is None else after.content.splitlines()
        diff = list(
            difflib.unified_diff(
                before_lines,
                after_lines,
                fromfile=f"a/{path}",
                tofile=f"b/{path}",
                lineterm="",
            )
        )
        added = sum(1 for line in diff if line.startswith("+") and not line.startswith("+++"))
        removed = sum(1 for line in diff if line.startswith("-") and not line.startswith("---"))
        dangerous_additions = sorted(
            {
                finding.title
                for finding in findings
                if finding.file_path == path and finding.severity in {"high", "critical"}
            }
        )
        unified_diff = "\n".join(diff)
        if binary_changed:
            if before is None or after is None:
                raise ValueError("binary_changed requires both before and after files")
            unified_diff = f"[binary changed] sha256 {before.sha256[:12]} -> {after.sha256[:12]}"
        elif binary_added:
            if after is None:
                raise ValueError("binary_added requires after file")
            unified_diff = f"[binary added] sha256 {after.sha256[:12]}"
        elif binary_removed:
            if before is None:
                raise ValueError("binary_removed requires before file")
            unified_diff = f"[binary removed] sha256 {before.sha256[:12]}"
        entries.append(
            DiffEntry(
                path=path,
                added_lines=added,
                removed_lines=removed,
                unified_diff=unified_diff,
                dangerous_additions=dangerous_additions,
            )
        )
    return entries


def render_risk_summary(
    *,
    skill: SkillBundle,
    findings: list[Finding],
    signature: VerificationResult,
) -> str:
    severities = {
        "critical": sum(1 for finding in findings if finding.severity == "critical"),
        "high": sum(1 for finding in findings if finding.severity == "high"),
        "medium": sum(1 for finding in findings if finding.severity == "medium"),
        "low": sum(1 for finding in findings if finding.severity == "low"),
    }
    domains = sorted({domain.domain for domain in skill.manifest.capabilities.network})
    files = list_files(skill)
    external_refs = sum(len(item.external_refs) for item in files)

    return (
        f"SKILL: {skill.manifest.name} v{skill.manifest.version}\n"
        f"Author: {skill.manifest.author}\n"
        f"Source: {skill.manifest.source_repo}\n"
        f"Signature: {signature.status.value} ({signature.reason})\n"
        f"Files: {len(files)} total, external refs: {external_refs}\n"
        f"Declared network domains: {', '.join(domains) if domains else '(none)'}\n"
        "Findings:\n"
        f"  critical={severities['critical']} high={severities['high']} "
        f"medium={severities['medium']} low={severities['low']}"
    )
