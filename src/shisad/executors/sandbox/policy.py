"""Sandbox policy and environment sanitization components."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Protocol

from shisad.executors.sandbox.models import (
    EnvironmentPolicy,
    SandboxConfig,
    SandboxEnforcement,
    SandboxType,
)

_ESCAPE_SIGNAL_TOKENS = {
    "unshare",
    "nsenter",
    "setns",
    "mount",
    "chroot",
    "ptrace",
}
_SHELL_REDIRECT_RE = re.compile(r"(^|[^>])>([^>]|$)")


class SandboxPolicyComponent(Protocol):
    """Protocol for sandbox policy evaluation and input sanitization."""

    def select_backend(self, config: SandboxConfig) -> SandboxType: ...

    def degraded_controls(
        self,
        config: SandboxConfig,
        enforcement: SandboxEnforcement,
    ) -> list[str]: ...

    def build_environment(
        self,
        policy: EnvironmentPolicy,
        requested: dict[str, str],
    ) -> tuple[dict[str, str], str | None, list[str]]: ...

    def escape_signal_reason(self, command: list[str]) -> str | None: ...

    def is_destructive(self, command: list[str]) -> bool: ...


class SandboxPolicyEvaluator:
    """Default policy evaluator used by sandbox orchestrator."""

    def select_backend(self, config: SandboxConfig) -> SandboxType:
        if config.sandbox_type is not None:
            return config.sandbox_type
        if config.network.allow_network or config.network_urls:
            return SandboxType.CONTAINER
        if config.write_paths or config.read_paths:
            return SandboxType.NSJAIL
        return SandboxType.NSJAIL

    def degraded_controls(
        self,
        config: SandboxConfig,
        enforcement: SandboxEnforcement,
    ) -> list[str]:
        required: set[str] = {"filesystem", "network", "env", "resource_limits"}
        if config.network.allow_network or config.network_urls:
            required.add("dns_control")
        if config.security_critical:
            required.add("seccomp")

        degraded: list[str] = []
        capability_map = {
            "filesystem": enforcement.filesystem,
            "network": enforcement.network,
            "env": enforcement.env,
            "seccomp": enforcement.seccomp,
            "resource_limits": enforcement.resource_limits,
            "cgroups": enforcement.cgroups,
            "dns_control": enforcement.dns_control,
        }
        for control in sorted(required):
            if not capability_map.get(control, False):
                degraded.append(control)
        return degraded

    def build_environment(
        self,
        policy: EnvironmentPolicy,
        requested: dict[str, str],
    ) -> tuple[dict[str, str], str | None, list[str]]:
        defaults: dict[str, str] = {}
        for key in policy.allowed_keys:
            if key in os.environ:
                defaults[key] = os.environ[key]

        sanitized = dict(defaults)
        dropped_keys: list[str] = []
        for key, value in requested.items():
            if key not in policy.allowed_keys:
                dropped_keys.append(key)
                continue
            if any(key.startswith(prefix) for prefix in policy.denied_prefixes):
                return {}, f"env_key_denied:{key}", dropped_keys
            sanitized[key] = value

        if len(sanitized) > policy.max_keys:
            return {}, "env_too_many_keys", dropped_keys
        total_bytes = 0
        for key, value in sanitized.items():
            total_bytes += len(key.encode("utf-8")) + len(value.encode("utf-8")) + 1
        if total_bytes > policy.max_total_bytes:
            return {}, "env_too_large", dropped_keys
        return sanitized, None, dropped_keys

    def is_destructive(self, command: list[str]) -> bool:
        if not command:
            return False
        executable = Path(command[0]).name
        if executable in {"rm", "rmdir", "truncate", "dd", "shred"}:
            return True
        if executable in {"mv", "chmod", "chown"}:
            return True
        if executable == "cp" and len(command) >= 3 and command[1] == "/dev/null":
            return True
        if executable == "sed" and any(arg == "-i" or arg.startswith("-i") for arg in command[1:]):
            return True
        if executable == "tee" and "-a" not in command[1:]:
            return True
        if executable == "git":
            if len(command) < 2:
                return False
            subcommand = command[1]
            args = command[2:]
            if subcommand == "reset" and any(
                arg == "--hard" or arg.startswith("--hard=") for arg in command[2:]
            ):
                return True
            if subcommand == "clean":
                flag_tokens = [arg for arg in args if arg.startswith("-")]
                if any("f" in token for token in flag_tokens) or "--force" in args:
                    return True
            if subcommand == "push" and any(
                arg in {"-f", "--force", "--force-with-lease"} or arg.startswith("--force")
                for arg in command[2:]
            ):
                return True
        return executable in {"sh", "bash", "zsh"} and any(
            _SHELL_REDIRECT_RE.search(token) for token in command[1:]
        )

    def escape_signal_reason(self, command: list[str]) -> str | None:
        lowered = " ".join(command).lower()
        for token in _ESCAPE_SIGNAL_TOKENS:
            if re.search(rf"\b{re.escape(token)}\b", lowered):
                return f"escape_signal:{token}"
        return None


__all__ = ["SandboxPolicyComponent", "SandboxPolicyEvaluator"]
