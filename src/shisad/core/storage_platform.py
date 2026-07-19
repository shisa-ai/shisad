"""Bounded platform capabilities for small state-file publication."""

from __future__ import annotations

import contextlib
import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class StorageCapability:
    """Truthful host support observed while publishing one state file."""

    parent_sync: str = "unsupported"
    permissions: str = "unsupported"


def combine_permission_capabilities(*states: str) -> str:
    """Combine attempts without treating unavailable host semantics as failure."""

    if "failed" in states:
        return "failed"
    return "supported" if states and all(item == "supported" for item in states) else "unsupported"


def tighten_permissions(path: Path, mode: int) -> str:
    """Apply a POSIX-style mode when the host supports it."""

    if os.name != "posix":
        return "unsupported"
    try:
        os.chmod(path, mode)
    except (AttributeError, NotImplementedError):
        return "unsupported"
    except OSError:
        return "failed"
    return "supported"


def sync_parent_directory(parent: Path) -> str:
    """Sync a directory only on hosts exposing the required POSIX capability."""

    if os.name != "posix" or not hasattr(os, "O_DIRECTORY"):
        return "unsupported"
    descriptor = -1
    try:
        flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0)
        descriptor = os.open(parent, flags)
        os.fsync(descriptor)
    finally:
        if descriptor >= 0:
            with contextlib.suppress(OSError):
                os.close(descriptor)
    return "supported"


def hardened_open_flags(base_flags: int) -> int:
    """Add optional POSIX no-follow/non-blocking flags in the platform adapter."""

    flags = base_flags
    for name in ("O_NOFOLLOW", "O_NONBLOCK"):
        flags |= int(getattr(os, name, 0))
    return flags
