"""Runtime capability-bounded sandbox checks for skills."""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, Field

from shisad.skills.manifest import SkillManifest


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

        allowed_commands = {item.command.strip() for item in manifest.capabilities.shell}
        for command in request.shell_commands:
            normalized = command.strip()
            if normalized and normalized not in allowed_commands:
                violations.append(f"undeclared_shell:{normalized}")

        allowed_env = {item.var.upper() for item in manifest.capabilities.environment}
        for env_name in request.environment_vars:
            normalized = env_name.strip().upper()
            if normalized and normalized not in allowed_env:
                violations.append(f"undeclared_env:{normalized}")

        allowed_paths = [
            Path(item.path).expanduser() for item in manifest.capabilities.filesystem
        ]
        for raw_path in request.filesystem_paths:
            path = Path(raw_path).expanduser()
            if self._violates_isolation(path, manifest.name):
                violations.append(f"isolation_violation:{raw_path}")
                continue
            if allowed_paths and not any(
                _path_within(path, allowed) for allowed in allowed_paths
            ):
                violations.append(f"undeclared_filesystem:{raw_path}")

        if violations:
            return SkillSandboxDecision(
                allowed=False,
                reason="undeclared_capability",
                violations=sorted(set(violations)),
            )
        return SkillSandboxDecision(allowed=True, reason="allowed")

    def _violates_isolation(self, path: Path, skill_name: str) -> bool:
        resolved = path.resolve()
        config_root = self._config_root.resolve()
        if _path_within(resolved, config_root):
            return True

        skills_root = self._skills_root.resolve()
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
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False
