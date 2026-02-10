"""Profile-then-lock workflow utilities for skills."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from shisad.skills.manifest import (
    EnvironmentCapability,
    FilesystemCapability,
    NetworkCapability,
    ShellCapability,
    SkillCapabilities,
    SkillManifest,
)


@dataclass(slots=True)
class CapabilityProfile:
    network_domains: set[str] = field(default_factory=set)
    filesystem_paths: set[str] = field(default_factory=set)
    shell_commands: set[str] = field(default_factory=set)
    environment_vars: set[str] = field(default_factory=set)

    def to_json(self) -> dict[str, Any]:
        return {
            "network_domains": sorted(self.network_domains),
            "filesystem_paths": sorted(self.filesystem_paths),
            "shell_commands": sorted(self.shell_commands),
            "environment_vars": sorted(self.environment_vars),
        }


class SkillProfiler:
    """Collect observed capability usage while running in profile mode."""

    def __init__(self) -> None:
        self._profile = CapabilityProfile()

    @property
    def profile(self) -> CapabilityProfile:
        return self._profile

    def record_network(self, host: str) -> None:
        if host.strip():
            self._profile.network_domains.add(host.strip().lower())

    def record_filesystem(self, path: str) -> None:
        if path.strip():
            self._profile.filesystem_paths.add(path.strip())

    def record_shell(self, command: str) -> None:
        if command.strip():
            self._profile.shell_commands.add(command.strip())

    def record_environment(self, var_name: str) -> None:
        if var_name.strip():
            self._profile.environment_vars.add(var_name.strip().upper())

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self._profile.to_json(), indent=2), encoding="utf-8")

    @classmethod
    def load(cls, path: Path) -> SkillProfiler:
        profiler = cls()
        if not path.exists():
            return profiler
        payload = json.loads(path.read_text(encoding="utf-8"))
        profiler._profile.network_domains = set(payload.get("network_domains", []))
        profiler._profile.filesystem_paths = set(payload.get("filesystem_paths", []))
        profiler._profile.shell_commands = set(payload.get("shell_commands", []))
        profiler._profile.environment_vars = set(payload.get("environment_vars", []))
        return profiler


def generate_manifest_from_profile(
    *,
    profile: CapabilityProfile,
    name: str,
    author: str,
    source_repo: str,
    version: str = "1.0.0",
    description: str = "",
) -> SkillManifest:
    capabilities = SkillCapabilities(
        network=[
            NetworkCapability(domain=host, reason="Observed during profile run")
            for host in sorted(profile.network_domains)
        ],
        filesystem=[
            FilesystemCapability(
                path=path,
                access="read-write",
                reason="Observed during profile run",
            )
            for path in sorted(profile.filesystem_paths)
        ],
        shell=[
            ShellCapability(command=cmd, reason="Observed during profile run")
            for cmd in sorted(profile.shell_commands)
        ],
        environment=[
            EnvironmentCapability(var=var_name, reason="Observed during profile run")
            for var_name in sorted(profile.environment_vars)
        ],
    )
    manifest = SkillManifest(
        name=name,
        version=version,
        author=author,
        signature="",
        source_repo=source_repo,
        description=description,
        capabilities=capabilities,
        dependencies=[],
    )
    return manifest


def lock_skill_manifest(manifest: SkillManifest, lock_file: Path) -> str:
    digest = manifest.manifest_hash()
    lock_file.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "manifest_hash": digest,
        "name": manifest.name,
        "version": manifest.version,
    }
    lock_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return digest
