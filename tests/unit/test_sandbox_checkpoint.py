"""M3 checkpoint component extraction coverage."""

from __future__ import annotations

from pathlib import Path

import pytest

from shisad.core.session import CheckpointStore, SessionManager
from shisad.daemon.handlers._impl import HandlerImplementation
from shisad.executors.sandbox import SandboxCheckpointManager, SandboxConfig
from shisad.executors.sandbox import checkpoint as checkpoint_module


def test_checkpoint_restores_deleted_directory_contents(tmp_path: Path) -> None:
    root = tmp_path / "workspace"
    target = root / "subdir" / "notes.txt"
    target.parent.mkdir(parents=True)
    target.write_text("keep these notes", encoding="utf-8")
    manager = SandboxCheckpointManager(checkpoint_store=None, audit_hook=None)
    snapshots = manager.capture_filesystem_snapshot([str(root)])
    target.unlink()
    target.parent.rmdir()
    root.rmdir()
    restored, deleted, errors = HandlerImplementation._restore_filesystem_from_checkpoint(
        {"filesystem_snapshot": snapshots}
    )
    assert (restored, deleted, errors) == (1, 0, [])
    assert target.read_text(encoding="utf-8") == "keep these notes"


@pytest.mark.parametrize("skipped", ["file_too_large", "read_error", ""])
def test_checkpoint_restore_reports_missing_content(tmp_path: Path, skipped: str) -> None:
    entry = {"path": str(tmp_path / "lost.bin"), "existed": True}
    if skipped:
        entry["snapshot_skipped"] = skipped
    restored, deleted, errors = HandlerImplementation._restore_filesystem_from_checkpoint(
        {"filesystem_snapshot": [entry]}
    )
    assert (restored, deleted) == (0, 0)
    assert errors == [f"{entry['path']}:{skipped or 'content_unavailable'}"]


def test_checkpoint_capture_does_not_follow_symlink(tmp_path: Path) -> None:
    target = tmp_path / "outside.txt"
    target.write_text("outside content", encoding="utf-8")
    link = tmp_path / "link"
    link.symlink_to(target)
    manager = SandboxCheckpointManager(checkpoint_store=None, audit_hook=None)
    snapshots = manager.capture_filesystem_snapshot([str(link)])
    assert snapshots[0]["snapshot_skipped"] == "symlink"
    assert "content_b64" not in snapshots[0]


@pytest.mark.parametrize("budget", ["bytes", "entries"])
def test_checkpoint_reports_exhausted_capture_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, budget: str
) -> None:
    root = tmp_path / "workspace"
    root.mkdir()
    for name in ("a", "b", "c"):
        (root / name).write_bytes(b"12345")
    monkeypatch.setattr(checkpoint_module, "_CHECKPOINT_TOTAL_SNAPSHOT_LIMIT", 6)
    monkeypatch.setattr(
        checkpoint_module, "_CHECKPOINT_ENTRY_LIMIT", 2 if budget == "entries" else 10
    )
    manager = SandboxCheckpointManager(checkpoint_store=None, audit_hook=None)
    snapshots = manager.capture_filesystem_snapshot([str(root)])
    skips = [entry.get("snapshot_skipped") for entry in snapshots]
    assert ("entry_limit" if budget == "entries" else "byte_limit") in skips
    _, _, errors = HandlerImplementation._restore_filesystem_from_checkpoint(
        {"filesystem_snapshot": snapshots}
    )
    assert errors


def test_checkpoint_restore_refuses_replaced_symlink_parent(tmp_path: Path) -> None:
    root = tmp_path / "workspace"
    root.mkdir()
    target = root / "notes.txt"
    target.write_text("original", encoding="utf-8")
    manager = SandboxCheckpointManager(checkpoint_store=None, audit_hook=None)
    snapshots = manager.capture_filesystem_snapshot([str(target)])
    target.unlink()
    root.rmdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    root.symlink_to(outside, target_is_directory=True)
    _, _, errors = HandlerImplementation._restore_filesystem_from_checkpoint(
        {"filesystem_snapshot": snapshots}
    )
    assert errors == [f"{target}:symlink"]
    assert not (outside / "notes.txt").exists()


@pytest.mark.parametrize(
    ("snapshots", "expected"),
    [
        (None, "invalid_filesystem_snapshot"),
        ([None], "invalid_snapshot_entry"),
        ([{}], "missing_snapshot_path"),
    ],
)
def test_checkpoint_restore_reports_invalid_manifest(snapshots: object, expected: str) -> None:
    assert HandlerImplementation._restore_filesystem_from_checkpoint(
        {"filesystem_snapshot": snapshots}
    ) == (0, 0, [expected])


def test_checkpoint_reports_read_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = tmp_path / "unreadable"
    target.write_bytes(b"content")

    def denied(*args: object, **kwargs: object) -> None:
        raise PermissionError("cannot read")

    monkeypatch.setattr(Path, "open", denied)
    manager = SandboxCheckpointManager(checkpoint_store=None, audit_hook=None)
    snapshots = manager.capture_filesystem_snapshot([str(target)])
    assert snapshots[0]["snapshot_skipped"] == "read_error"


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
