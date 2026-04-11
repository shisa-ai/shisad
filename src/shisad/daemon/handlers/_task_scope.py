"""Shared TASK/background scope helpers."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from shisad.core.types import UserId, WorkspaceId

_PATH_RESOURCE_ARG_NAMES = frozenset({"path", "repo_path"})


def _has_semantic_resource_marker(value: str) -> bool:
    normalized = value.strip()
    return "://" in normalized or ":" in normalized.split("/", 1)[0].split("\\", 1)[0]


def _filesystem_bases(filesystem_roots: Sequence[Path | str] | None) -> tuple[Path, ...]:
    roots: list[Path] = []
    for raw_root in filesystem_roots or ():
        normalized = str(raw_root).strip()
        if not normalized:
            continue
        roots.append(Path(normalized).expanduser().resolve(strict=False))
    return tuple(roots) or (Path.cwd().expanduser().resolve(strict=False),)


def _path_from_scope(value: str, base: Path) -> Path:
    candidate = Path(value).expanduser()
    if not candidate.is_absolute():
        candidate = base / candidate
    return candidate


def _looks_like_filesystem_scope(value: str, *, base: Path) -> bool:
    normalized = value.strip()
    if not normalized:
        return False
    if _has_semantic_resource_marker(normalized):
        return False
    if normalized in {".", ".."}:
        return True
    if normalized.startswith(("/", "./", "../", "~")):
        return True
    if "/" in normalized or "\\" in normalized:
        return True
    try:
        if _path_from_scope(normalized, base).exists():
            return True
    except OSError:
        return False
    return "." in Path(normalized).name


def _canonical_filesystem_scope(value: str, *, base: Path) -> Path:
    return _path_from_scope(value, base).resolve(strict=False)


def _filesystem_scope_matches(candidate: Path, prefix: Path) -> bool:
    return candidate == prefix or prefix in candidate.parents


class _TaskResourceAuthorizer:
    def __init__(
        self,
        *,
        allowed_ids: set[str],
        allowed_prefixes: tuple[str, ...],
        filesystem_base: Path,
    ) -> None:
        self._allowed_ids = frozenset(allowed_ids)
        self._semantic_allowed_prefixes = tuple(
            item
            for item in allowed_prefixes
            if not _looks_like_filesystem_scope(item, base=filesystem_base)
        )
        self._filesystem_allowed_ids = frozenset(
            _canonical_filesystem_scope(item, base=filesystem_base)
            for item in allowed_ids
            if _looks_like_filesystem_scope(item, base=filesystem_base)
        )
        self._filesystem_allowed_prefixes = tuple(
            _canonical_filesystem_scope(item, base=filesystem_base)
            for item in allowed_prefixes
            if _looks_like_filesystem_scope(item, base=filesystem_base)
        )
        self._filesystem_base = filesystem_base

    def __call__(
        self,
        resource_id: str,
        _workspace_id: WorkspaceId,
        _user_id: UserId,
    ) -> bool:
        return self._authorize(resource_id, filesystem_scope=True)

    def authorize_argument(
        self,
        argument_name: str,
        resource_id: str,
        _workspace_id: WorkspaceId,
        _user_id: UserId,
    ) -> bool:
        return self._authorize(
            resource_id,
            filesystem_scope=argument_name in _PATH_RESOURCE_ARG_NAMES,
        )

    def _authorize(self, resource_id: str, *, filesystem_scope: bool) -> bool:
        normalized = str(resource_id).strip()
        if not normalized:
            return False
        if normalized in self._allowed_ids:
            return True
        if any(normalized.startswith(prefix) for prefix in self._semantic_allowed_prefixes):
            return True
        if not filesystem_scope:
            return False
        if not _looks_like_filesystem_scope(normalized, base=self._filesystem_base):
            return False
        canonical = _canonical_filesystem_scope(normalized, base=self._filesystem_base)
        if canonical in self._filesystem_allowed_ids:
            return True
        return any(
            _filesystem_scope_matches(canonical, prefix)
            for prefix in self._filesystem_allowed_prefixes
        )


def task_resource_authorizer(
    task_envelope: Any,
    *,
    filesystem_roots: Sequence[Path | str] | None = None,
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
    filesystem_base = _filesystem_bases(filesystem_roots)[0]
    return _TaskResourceAuthorizer(
        allowed_ids=allowed_ids,
        allowed_prefixes=allowed_prefixes,
        filesystem_base=filesystem_base,
    )


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
