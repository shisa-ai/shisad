"""Filesystem mount policy evaluation for sandboxed tool execution."""

from __future__ import annotations

import fnmatch
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

MountMode = Literal["ro", "rw", "none"]


class MountRule(BaseModel):
    """Allowlist mount rule."""

    path: str
    mode: MountMode = "ro"


class FilesystemPolicy(BaseModel):
    """Filesystem policy for a tool execution."""

    mounts: list[MountRule] = Field(default_factory=list)
    denylist: list[str] = Field(default_factory=list)


class FilesystemAccessDecision(BaseModel):
    """Result of evaluating one path access attempt."""

    allowed: bool
    path: str
    write: bool = False
    reason: str = ""
    matched_mount: str = ""
    mode: MountMode = "none"


class MountManager:
    """Evaluates filesystem accesses against mount and denylist policy."""

    def __init__(self, policy: FilesystemPolicy, *, home: Path | None = None) -> None:
        self._policy = policy
        self._home = home or Path.home()

    def check_access(self, path: str, *, write: bool) -> FilesystemAccessDecision:
        """Evaluate a single path access attempt."""
        normalized = self._normalize_path(path)
        normalized_str = normalized.as_posix()

        for pattern in self._policy.denylist:
            if self._matches(normalized, pattern):
                return FilesystemAccessDecision(
                    allowed=False,
                    path=normalized_str,
                    write=write,
                    reason="denylist_match",
                    matched_mount="",
                    mode="none",
                )

        for mount in self._policy.mounts:
            if not self._matches(normalized, mount.path):
                continue
            if mount.mode == "none":
                return FilesystemAccessDecision(
                    allowed=False,
                    path=normalized_str,
                    write=write,
                    reason="mount_disabled",
                    matched_mount=mount.path,
                    mode=mount.mode,
                )
            if write and mount.mode == "ro":
                return FilesystemAccessDecision(
                    allowed=False,
                    path=normalized_str,
                    write=write,
                    reason="read_only_mount",
                    matched_mount=mount.path,
                    mode=mount.mode,
                )
            return FilesystemAccessDecision(
                allowed=True,
                path=normalized_str,
                write=write,
                reason="allowed",
                matched_mount=mount.path,
                mode=mount.mode,
            )

        return FilesystemAccessDecision(
            allowed=False,
            path=normalized_str,
            write=write,
            reason="outside_mounts",
            matched_mount="",
            mode="none",
        )

    def _normalize_path(self, path: str) -> Path:
        expanded = path
        if expanded.startswith("~/"):
            expanded = str(self._home / expanded[2:])
        return Path(expanded).expanduser().resolve(strict=False)

    def _matches(self, path: Path, pattern: str) -> bool:
        normalized_pattern = pattern
        if normalized_pattern.startswith("~/"):
            normalized_pattern = str(self._home / normalized_pattern[2:])
        path_str = path.as_posix()
        if normalized_pattern.startswith("/"):
            normalized_pattern = (
                Path(normalized_pattern).expanduser().resolve(strict=False).as_posix()
            )
            if fnmatch.fnmatch(path_str, normalized_pattern):
                return True
            return fnmatch.fnmatch(path_str + "/", normalized_pattern)

        relative_path = path_str.lstrip("/")
        if fnmatch.fnmatch(relative_path, normalized_pattern):
            return True
        if fnmatch.fnmatch(path.name, normalized_pattern):
            return True
        return fnmatch.fnmatch(path_str, normalized_pattern)
