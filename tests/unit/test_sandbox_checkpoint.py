"""M3 checkpoint component extraction coverage."""

from __future__ import annotations

from pathlib import Path

from shisad.core.session import CheckpointStore, SessionManager
from shisad.executors.sandbox import SandboxCheckpointManager, SandboxConfig


def test_m3_checkpoint_creates_snapshot_for_destructive_command(tmp_path: Path) -> None:
    checkpoint_store = CheckpointStore(tmp_path / "checkpoints")
    session = SessionManager().create(channel="cli")
    target = tmp_path / "notes.txt"
    target.write_text("hello", encoding="utf-8")
    manager = SandboxCheckpointManager(
        checkpoint_store=checkpoint_store,
        audit_hook=None,
    )
    checkpoint_id = manager.maybe_create_pre_execution_checkpoint(
        config=SandboxConfig(
            tool_name="file.write",
            command=["rm", "-f", str(target)],
            write_paths=[str(target)],
        ),
        command=["rm", "-f", str(target)],
        session=session,
        is_destructive=lambda command: command[0] == "rm",
    )
    checkpoints = checkpoint_store.list_for_session(session.id)
    assert checkpoint_id
    assert checkpoints
    snapshot = checkpoints[0].state["filesystem_snapshot"]
    assert snapshot[0]["path"] == str(target)


def test_m3_checkpoint_skip_when_store_or_session_missing(tmp_path: Path) -> None:
    manager = SandboxCheckpointManager(
        checkpoint_store=None,
        audit_hook=None,
    )
    checkpoint_id = manager.maybe_create_pre_execution_checkpoint(
        config=SandboxConfig(
            tool_name="shell.exec",
            command=["echo", "ok"],
        ),
        command=["echo", "ok"],
        session=None,
        is_destructive=lambda command: bool(command),
    )
    assert checkpoint_id == ""


def test_m3_checkpoint_snapshot_marks_large_file_as_skipped(tmp_path: Path) -> None:
    target = tmp_path / "huge.bin"
    target.write_bytes(b"a" * 1_000_100)
    manager = SandboxCheckpointManager(
        checkpoint_store=None,
        audit_hook=None,
    )
    snapshot = manager.capture_filesystem_snapshot([str(target)])
    assert snapshot
    assert snapshot[0]["snapshot_skipped"] == "file_too_large"
