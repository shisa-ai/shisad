"""Sandbox checkpoint/snapshot helper component."""

from __future__ import annotations

import base64
import os
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from shisad.core.session import CheckpointStore, Session
from shisad.executors.sandbox.models import SandboxConfig

_CHECKPOINT_FILE_SNAPSHOT_LIMIT = 1_000_000
_CHECKPOINT_TOTAL_SNAPSHOT_LIMIT = 16_000_000
_CHECKPOINT_ENTRY_LIMIT = 1024


class SandboxCheckpointComponent(Protocol):
    """Protocol for sandbox checkpoint helper component."""

    def maybe_create_pre_execution_checkpoint(
        self,
        *,
        config: SandboxConfig,
        command: list[str],
        session: Session | None,
        is_destructive: Callable[[list[str]], bool],
    ) -> str: ...

    def capture_filesystem_snapshot(self, paths: list[str]) -> list[dict[str, Any]]: ...


class SandboxCheckpointManager:
    """Checkpoint helper used by sandbox orchestrator."""

    def __init__(
        self,
        *,
        checkpoint_store: CheckpointStore | None,
        audit_hook: Callable[[dict[str, object]], None] | None,
    ) -> None:
        self._checkpoint_store = checkpoint_store
        self._audit_hook = audit_hook

    def maybe_create_pre_execution_checkpoint(
        self,
        *,
        config: SandboxConfig,
        command: list[str],
        session: Session | None,
        is_destructive: Callable[[list[str]], bool],
    ) -> str:
        if self._checkpoint_store is None or session is None or not is_destructive(config.command):
            return ""
        checkpoint = self._checkpoint_store.create(
            session,
            state={
                "session": session.model_dump(mode="json"),
                "tool_name": config.tool_name,
                "command": list(command),
                "write_paths": list(config.write_paths),
                "filesystem_snapshot": self.capture_filesystem_snapshot(config.write_paths),
                "created_at": datetime.now(UTC).isoformat(),
            },
        )
        checkpoint_id = checkpoint.checkpoint_id
        if self._audit_hook is not None:
            self._audit_hook(
                {
                    "action": "sandbox.pre_checkpoint",
                    "session_id": config.session_id,
                    "checkpoint_id": checkpoint_id,
                    "tool_name": config.tool_name,
                }
            )
        return checkpoint_id

    def capture_filesystem_snapshot(self, paths: list[str]) -> list[dict[str, Any]]:
        snapshots: list[dict[str, Any]] = []
        seen: set[str] = set()
        pending = [Path(raw).expanduser().absolute() for raw in reversed(paths)]
        total_bytes = 0
        while pending:
            candidate = pending.pop()
            normalized = str(candidate)
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            entry: dict[str, Any] = {"path": normalized, "existed": candidate.exists()}
            snapshots.append(entry)
            try:
                if candidate.is_symlink() or any(
                    parent.is_symlink() for parent in candidate.parents
                ):
                    entry["snapshot_skipped"] = "symlink"
                elif len(snapshots) > _CHECKPOINT_ENTRY_LIMIT:
                    entry["snapshot_skipped"] = "entry_limit"
                elif candidate.is_dir():
                    entry["kind"] = "directory"
                    with os.scandir(candidate) as children:
                        for child in children:
                            if len(snapshots) + len(pending) >= _CHECKPOINT_ENTRY_LIMIT:
                                entry["snapshot_skipped"] = "entry_limit"
                                break
                            pending.append(Path(child.path))
                elif candidate.is_file():
                    remaining = _CHECKPOINT_TOTAL_SNAPSHOT_LIMIT - total_bytes
                    limit = min(_CHECKPOINT_FILE_SNAPSHOT_LIMIT, remaining)
                    with candidate.open("rb") as stream:
                        data = stream.read(limit + 1)
                    if len(data) > limit:
                        entry["snapshot_skipped"] = (
                            "file_too_large"
                            if limit == _CHECKPOINT_FILE_SNAPSHOT_LIMIT
                            else "byte_limit"
                        )
                    else:
                        entry["content_b64"] = base64.b64encode(data).decode("utf-8")
                        total_bytes += len(data)
                elif candidate.exists():
                    entry["snapshot_skipped"] = "unsupported_file_type"
            except OSError:
                entry["snapshot_skipped"] = "read_error"
        return snapshots


__all__ = [
    "SandboxCheckpointComponent",
    "SandboxCheckpointManager",
]
