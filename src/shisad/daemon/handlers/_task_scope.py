"""Shared TASK/background scope helpers."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from shisad.core.types import UserId, WorkspaceId


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

    def _authorize(resource_id: str, _workspace_id: WorkspaceId, _user_id: UserId) -> bool:
        normalized = str(resource_id).strip()
        if not normalized:
            return False
        if normalized in allowed_ids:
            return True
        return any(normalized.startswith(prefix) for prefix in allowed_prefixes)

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
