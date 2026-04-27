"""Runtime capability-bounded sandbox checks for skills."""

from __future__ import annotations

import re
from pathlib import Path

from pydantic import BaseModel, Field

from shisad.core.url_parsing import safe_url_hostname
from shisad.skills.manifest import SkillManifest

_URL_RE = re.compile(r"https?://[^\s'\"<>`]+", re.IGNORECASE)


class SkillSandboxDecision(BaseModel):
    allowed: bool
    reason: str = ""
    violations: list[str] = Field(default_factory=list)


class SkillExecutionRequest(BaseModel):
    skill_name: str
    network_hosts: list[str] = Field(default_factory=list)
    filesystem_paths: list[str] = Field(default_factory=list)
    shell_commands: list[str] = Field(default_factory=list)
    environment_vars: list[str] = Field(default_factory=list)


class SkillRuntimeSandbox:
    """Checks runtime requests against declared manifest capabilities."""

    def __init__(self, *, skills_root: Path, config_root: Path) -> None:
        self._skills_root = skills_root
        self._config_root = config_root

    def authorize(
        self,
        manifest: SkillManifest,
        request: SkillExecutionRequest,
    ) -> SkillSandboxDecision:
        violations: list[str] = []

        allowed_domains = {item.domain.lower() for item in manifest.capabilities.network}
        for host in request.network_hosts:
            normalized = host.strip().lower()
            if normalized and normalized not in allowed_domains:
                violations.append(f"undeclared_network:{normalized}")

        allowed_commands = [
            _normalize_command(item.command)
            for item in manifest.capabilities.shell
            if item.command.strip()
        ]
        for command in request.shell_commands:
            normalized = _normalize_command(command)
            if not normalized:
                continue
            if not any(_shell_command_matches(normalized, allowed) for allowed in allowed_commands):
                violations.append(f"undeclared_shell:{normalized}")

        allowed_env = {item.var.upper() for item in manifest.capabilities.environment}
        for env_name in request.environment_vars:
            normalized = env_name.strip().upper()
            if normalized and normalized not in allowed_env:
                violations.append(f"undeclared_env:{normalized}")

        allowed_paths = [
            _resolve_path(Path(item.path)) for item in manifest.capabilities.filesystem
        ]
        if not allowed_paths and request.filesystem_paths:
            for raw_path in request.filesystem_paths:
                if raw_path.strip():
                    violations.append(f"undeclared_filesystem:{raw_path}")
            if violations:
                return SkillSandboxDecision(
                    allowed=False,
                    reason="undeclared_capability",
                    violations=sorted(set(violations)),
                )
        for raw_path in request.filesystem_paths:
            path = _resolve_path(Path(raw_path))
            if self._violates_isolation(path, manifest.name):
                violations.append(f"isolation_violation:{raw_path}")
                continue
            if not any(_path_within(path, allowed) for allowed in allowed_paths):
                violations.append(f"undeclared_filesystem:{raw_path}")

        if violations:
            return SkillSandboxDecision(
                allowed=False,
                reason="undeclared_capability",
                violations=sorted(set(violations)),
            )
        return SkillSandboxDecision(allowed=True, reason="allowed")

    def _violates_isolation(self, path: Path, skill_name: str) -> bool:
        resolved = _resolve_path(path)
        config_root = _resolve_path(self._config_root)
        if _path_within(resolved, config_root):
            return True

        skills_root = _resolve_path(self._skills_root)
        if _path_within(resolved, skills_root):
            skill_root = skills_root / skill_name
            if not _path_within(resolved, skill_root):
                return True
        return False

    def profile_from_execution(
        self,
        request: SkillExecutionRequest,
    ) -> dict[str, list[str]]:
        """Structured profile output for profile-then-lock workflow."""

        return {
            "network": sorted({host.lower() for host in request.network_hosts if host.strip()}),
            "filesystem": sorted({path for path in request.filesystem_paths if path.strip()}),
            "shell": sorted({cmd for cmd in request.shell_commands if cmd.strip()}),
            "environment": sorted(
                {name.upper() for name in request.environment_vars if name.strip()}
            ),
        }


def _path_within(path: Path, parent: Path) -> bool:
    resolved_path = _resolve_path(path)
    resolved_parent = _resolve_path(parent)
    try:
        resolved_path.relative_to(resolved_parent)
        return True
    except ValueError:
        return False


def _resolve_path(path: Path) -> Path:
    return path.expanduser().resolve(strict=False)


def _normalize_command(command: str) -> str:
    return " ".join(command.strip().split())


def _shell_command_matches(inferred: str, declared: str) -> bool:
    inferred_norm = _normalize_command(inferred)
    declared_norm = _normalize_command(declared)
    if not inferred_norm or not declared_norm:
        return False
    if inferred_norm == declared_norm:
        return True
    if inferred_norm.startswith(declared_norm):
        return True
    inferred_head = inferred_norm.split(" ", 1)[0]
    declared_head = declared_norm.split(" ", 1)[0]
    if inferred_head != declared_head:
        return False
    declared_hosts = _extract_url_hosts(declared_norm)
    if not declared_hosts:
        return True
    inferred_hosts = _extract_url_hosts(inferred_norm)
    if not inferred_hosts:
        return False
    return inferred_hosts.issubset(declared_hosts)


def _extract_url_hosts(value: str) -> set[str]:
    hosts: set[str] = set()
    for token in _URL_RE.findall(value):
        host = safe_url_hostname(token)
        if host:
            hosts.add(host)
    return hosts
