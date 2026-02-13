"""Sandbox checkpoint/snapshot helper component."""

from __future__ import annotations

import base64
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from shisad.core.session import CheckpointStore, Session
from shisad.executors.sandbox.models import SandboxConfig

_CHECKPOINT_FILE_SNAPSHOT_LIMIT = 1_000_000


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
        for raw in paths:
            candidate = Path(raw).expanduser()
            normalized = str(candidate)
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            entry: dict[str, Any] = {"path": normalized, "existed": candidate.exists()}
            if candidate.exists() and candidate.is_file():
                try:
                    data = candidate.read_bytes()
                    if len(data) > _CHECKPOINT_FILE_SNAPSHOT_LIMIT:
                        entry["snapshot_skipped"] = "file_too_large"
                    else:
                        entry["content_b64"] = base64.b64encode(data).decode("utf-8")
                except OSError:
                    entry["snapshot_skipped"] = "read_error"
            snapshots.append(entry)
        return snapshots


__all__ = [
    "SandboxCheckpointComponent",
    "SandboxCheckpointManager",
]
