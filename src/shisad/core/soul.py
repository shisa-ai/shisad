"""Trusted SOUL.md persona preference helpers."""

from __future__ import annotations

import hashlib
import os
import re
import stat
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

DEFAULT_SOUL_MAX_BYTES = 64 * 1024
SOUL_FILENAME = "SOUL.md"

_PROJECT_SPECIFIC_RE = re.compile(
    r"(?i)\b("
    r"project|repo|repository|workspace|milestone|sprint|issue\s+#?\d+|"
    r"pull\s+request|pr\s+#?\d+|src/|tests/|docs/|github"
    r")\b"
)


class SoulFileError(ValueError):
    """Raised when a configured SOUL.md path or payload is unsafe."""


@dataclass(frozen=True)
class SoulWriteResult:
    """Result of a trusted SOUL.md write."""

    path: Path
    sha256: str
    bytes_written: int
    warnings: tuple[str, ...]


def validate_soul_path(raw_path: str | Path) -> Path:
    """Validate the configured SOUL.md path without following symlink escapes."""
    path = Path(raw_path).expanduser()
    if not path.is_absolute():
        raise SoulFileError("SOUL.md path must be absolute")
    if any(part == ".." for part in path.parts):
        raise SoulFileError("SOUL.md path traversal is not allowed")
    if path.name != SOUL_FILENAME:
        raise SoulFileError(f"SOUL.md path must end with {SOUL_FILENAME}")
    _reject_symlink_components(path)
    return path


def load_soul_text(raw_path: str | Path, *, max_bytes: int = DEFAULT_SOUL_MAX_BYTES) -> str:
    """Load trusted SOUL.md text from the configured operator path."""
    path = validate_soul_path(raw_path)
    _validate_max_bytes(max_bytes)
    if _existing_regular_soul_stat(path) is None:
        return ""
    flags = _soul_open_flags(os.O_RDONLY)
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        return ""
    except OSError as exc:
        raise SoulFileError(f"SOUL.md read failed: {exc}") from exc
    try:
        _validate_open_soul_regular_file(fd)
        with os.fdopen(fd, "rb") as handle:
            fd = -1
            data = handle.read(max_bytes + 1)
    finally:
        if fd >= 0:
            os.close(fd)
    if len(data) > max_bytes:
        raise SoulFileError(f"SOUL.md exceeds configured size limit ({max_bytes} bytes)")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SoulFileError("SOUL.md must be valid UTF-8") from exc


def load_effective_persona_text(config: Any) -> str:
    """Combine inline trusted persona config with configured SOUL.md preferences."""
    inline_text = str(getattr(config, "assistant_persona_custom_text", "") or "").strip()
    soul_path = getattr(config, "assistant_persona_soul_path", None)
    max_bytes = int(getattr(config, "assistant_persona_soul_max_bytes", DEFAULT_SOUL_MAX_BYTES))
    soul_text = load_soul_text(soul_path, max_bytes=max_bytes) if soul_path is not None else ""
    return combine_persona_text(inline_text=inline_text, soul_text=soul_text)


def combine_persona_text(*, inline_text: str = "", soul_text: str = "") -> str:
    """Format persona overlays so SOUL.md remains preference text, not policy."""
    parts: list[str] = []
    normalized_inline = inline_text.strip()
    if normalized_inline:
        parts.append(normalized_inline)
    normalized_soul = soul_text.strip()
    if normalized_soul:
        parts.append(f"SOUL.md persona preferences:\n{normalized_soul}")
    return "\n\n".join(parts).strip()


def soul_content_warnings(content: str) -> tuple[str, ...]:
    """Return deterministic warnings for content that belongs in memory instead."""
    warnings: list[str] = []
    if _PROJECT_SPECIFIC_RE.search(content):
        warnings.append("project_specific_memory_route_recommended")
    return tuple(warnings)


def write_soul_text(
    raw_path: str | Path,
    content: str,
    *,
    max_bytes: int = DEFAULT_SOUL_MAX_BYTES,
) -> SoulWriteResult:
    """Write trusted SOUL.md text to the configured operator path."""
    path = validate_soul_path(raw_path)
    _validate_max_bytes(max_bytes)
    normalized = str(content)
    data = normalized.encode("utf-8")
    if len(data) > max_bytes:
        raise SoulFileError(f"SOUL.md exceeds configured size limit ({max_bytes} bytes)")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    _reject_symlink_components(path)
    _existing_regular_soul_stat(path)
    flags = _soul_open_flags(os.O_WRONLY | os.O_CREAT | os.O_TRUNC)
    try:
        fd = os.open(path, flags, 0o600)
    except OSError as exc:
        raise SoulFileError(f"SOUL.md write failed: {exc}") from exc
    try:
        _validate_open_soul_regular_file(fd)
        with os.fdopen(fd, "wb") as handle:
            fd = -1
            handle.write(data)
    finally:
        if fd >= 0:
            os.close(fd)
    with suppress(PermissionError):
        path.chmod(0o600)
    return SoulWriteResult(
        path=path,
        sha256=_sha256_text(normalized),
        bytes_written=len(data),
        warnings=soul_content_warnings(normalized),
    )


def soul_text_sha256(content: str) -> str:
    """Return the API-facing sha256 value for SOUL.md text."""
    return _sha256_text(str(content))


def _sha256_text(content: str) -> str:
    return "sha256:" + hashlib.sha256(content.encode("utf-8")).hexdigest()


def _validate_max_bytes(max_bytes: int) -> None:
    if max_bytes < 1:
        raise SoulFileError("SOUL.md max_bytes must be positive")


def _existing_regular_soul_stat(path: Path) -> os.stat_result | None:
    try:
        file_stat = os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise SoulFileError(f"SOUL.md stat failed: {exc}") from exc
    if not stat.S_ISREG(file_stat.st_mode):
        raise SoulFileError("SOUL.md path must point to a regular file")
    return file_stat


def _soul_open_flags(base_flags: int) -> int:
    flags = base_flags
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    return flags


def _validate_open_soul_regular_file(fd: int) -> None:
    file_stat = os.fstat(fd)
    if not stat.S_ISREG(file_stat.st_mode):
        raise SoulFileError("SOUL.md path must point to a regular file")


def _reject_symlink_components(path: Path) -> None:
    for candidate in [*reversed(path.parents), path]:
        if candidate.is_symlink():
            raise SoulFileError("SOUL.md path must not contain symlinks")
