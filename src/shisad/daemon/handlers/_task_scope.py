"""Shared TASK/background scope helpers."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

from shisad.core.types import UserId, WorkspaceId


def _looks_like_filesystem_scope(value: str) -> bool:
    normalized = value.strip()
    if not normalized:
        return False
    if "://" in normalized:
        return False
    if ":" in normalized.split("/", 1)[0].split("\\", 1)[0]:
        return False
    if normalized.startswith(("/", "./", "../", "~")):
        return True
    if "/" in normalized or "\\" in normalized:
        return True
    return "." in Path(normalized).name


def _canonical_filesystem_scope(value: str) -> Path:
    return Path(value).expanduser().resolve(strict=False)


def _filesystem_scope_matches(candidate: Path, prefix: Path) -> bool:
    return candidate == prefix or prefix in candidate.parents


def task_resource_authorizer(
    task_envelope: Any,
) -> Callable[[str, WorkspaceId, UserId], bool] | None:
    if task_envelope is None:
        return None
    allowed_ids = {
        str(item).strip()
        for item in getattr(task_envelope, "resource_scope_ids", ())
        if str(item).strip()
    }
    allowed_prefixes = tuple(
        str(item).strip()
        for item in getattr(task_envelope, "resource_scope_prefixes", ())
        if str(item).strip()
    )
    if not allowed_ids and not allowed_prefixes:
        return None
    filesystem_allowed_ids = {
        _canonical_filesystem_scope(item)
        for item in allowed_ids
        if _looks_like_filesystem_scope(item)
    }
    filesystem_allowed_prefixes = tuple(
        _canonical_filesystem_scope(item)
        for item in allowed_prefixes
        if _looks_like_filesystem_scope(item)
    )
    semantic_allowed_prefixes = tuple(
        item for item in allowed_prefixes if not _looks_like_filesystem_scope(item)
    )

    def _authorize(resource_id: str, _workspace_id: WorkspaceId, _user_id: UserId) -> bool:
        normalized = str(resource_id).strip()
        if not normalized:
            return False
        if normalized in allowed_ids:
            return True
        if any(normalized.startswith(prefix) for prefix in semantic_allowed_prefixes):
            return True
        if not _looks_like_filesystem_scope(normalized):
            return False
        canonical = _canonical_filesystem_scope(normalized)
        if canonical in filesystem_allowed_ids:
            return True
        return any(
            _filesystem_scope_matches(canonical, prefix)
            for prefix in filesystem_allowed_prefixes
        )

    return _authorize


def task_declared_tdg_roots(task_envelope: Any) -> tuple[str, ...]:
    if task_envelope is None:
        return ()
    authority = str(getattr(task_envelope, "resource_scope_authority", "")).strip().lower()
    if authority != "command_clean":
        return ()
    roots: list[str] = []
    for raw in (
        *getattr(task_envelope, "resource_scope_ids", ()),
        *getattr(task_envelope, "resource_scope_prefixes", ()),
    ):
        normalized = str(raw).strip()
        if normalized and normalized not in roots:
            roots.append(normalized)
    return tuple(roots)
