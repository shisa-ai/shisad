"""Bounded no-follow staging for caller-controlled artifact trees."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

import shisad.core.artifact_staging as artifact_staging_module
from shisad.core.artifact_staging import (
    ArtifactTreeCopyError,
    capture_bounded_regular_tree,
    copy_bounded_regular_tree,
)


def test_artifact_staging_copies_only_regular_tree_with_owner_only_modes(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "nested").mkdir()
    (source / "root.txt").write_bytes(b"root")
    (source / "nested" / "child.txt").write_bytes(b"child")
    destination = tmp_path / "destination"

    result = copy_bounded_regular_tree(
        source,
        destination,
        max_entries=8,
        max_total_bytes=32,
    )

    assert result.entry_count == 3
    assert result.file_count == 2
    assert result.total_bytes == 9
    assert (destination / "nested" / "child.txt").read_bytes() == b"child"
    assert stat.S_IMODE(destination.stat().st_mode) == 0o700
    assert stat.S_IMODE((destination / "root.txt").stat().st_mode) == 0o600


def test_artifact_snapshot_captures_only_the_held_regular_file_bytes(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "nested").mkdir()
    (source / "root.txt").write_bytes(b"root")
    (source / "nested" / "child.txt").write_bytes(b"child")

    snapshot = capture_bounded_regular_tree(
        source,
        max_entries=8,
        max_total_bytes=32,
    )
    (source / "root.txt").write_bytes(b"changed after capture")

    assert snapshot.entry_count == 3
    assert snapshot.file_count == 2
    assert snapshot.total_bytes == 9
    assert dict(snapshot.files) == {
        "nested/child.txt": b"child",
        "root.txt": b"root",
    }


def test_artifact_snapshot_rejects_symlinks_without_reading_external_bytes(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    external = tmp_path / "secret.txt"
    external.write_text("secret", encoding="utf-8")
    (source / "escape").symlink_to(external)

    with pytest.raises(ArtifactTreeCopyError, match="symlink"):
        capture_bounded_regular_tree(
            source,
            max_entries=8,
            max_total_bytes=32,
        )


@pytest.mark.parametrize("link_to_directory", [False, True])
def test_artifact_staging_rejects_symlinks_without_copying_external_bytes(
    tmp_path: Path,
    link_to_directory: bool,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    external = tmp_path / "external"
    external.mkdir()
    secret = external / "secret.txt"
    secret.write_text("secret", encoding="utf-8")
    target = external if link_to_directory else secret
    (source / "escape").symlink_to(target, target_is_directory=link_to_directory)
    destination = tmp_path / "destination"

    with pytest.raises(ArtifactTreeCopyError, match="symlink"):
        copy_bounded_regular_tree(
            source,
            destination,
            max_entries=8,
            max_total_bytes=32,
        )

    assert not destination.exists()


def test_artifact_staging_rejects_special_files_without_opening_them(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    os.mkfifo(source / "stream")
    destination = tmp_path / "destination"

    with pytest.raises(ArtifactTreeCopyError, match="regular files and directories"):
        copy_bounded_regular_tree(
            source,
            destination,
            max_entries=8,
            max_total_bytes=32,
        )

    assert not destination.exists()


@pytest.mark.parametrize("destination_kind", ["same", "descendant", "ancestor"])
def test_artifact_staging_rejects_source_destination_overlap(
    tmp_path: Path,
    destination_kind: str,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "file.txt").write_text("payload", encoding="utf-8")
    if destination_kind == "same":
        destination = source
    elif destination_kind == "descendant":
        destination = source / "nested" / "destination"
    else:
        destination = tmp_path

    with pytest.raises(ArtifactTreeCopyError, match="overlap"):
        copy_bounded_regular_tree(
            source,
            destination,
            max_entries=8,
            max_total_bytes=32,
        )


@pytest.mark.parametrize(
    ("max_entries", "max_total_bytes", "match"),
    [
        (1, 32, "entry limit"),
        (8, 3, "byte limit"),
    ],
)
def test_artifact_staging_enforces_entry_and_total_byte_bounds(
    tmp_path: Path,
    max_entries: int,
    max_total_bytes: int,
    match: str,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "one.txt").write_bytes(b"one")
    (source / "two.txt").write_bytes(b"two")
    destination = tmp_path / "destination"

    with pytest.raises(ArtifactTreeCopyError, match=match):
        copy_bounded_regular_tree(
            source,
            destination,
            max_entries=max_entries,
            max_total_bytes=max_total_bytes,
        )

    assert not destination.exists()


def test_artifact_staging_rejects_file_swapped_to_fifo_without_blocking(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    source_file = source / "payload.txt"
    source_file.write_bytes(b"approved")
    destination = tmp_path / "destination"
    original_open = os.open
    swapped = False

    def _open_after_swap(
        path: str | bytes | Path,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal swapped
        if (
            path == "payload.txt"
            and dir_fd is not None
            and flags & (os.O_WRONLY | os.O_RDWR) == 0
            and not swapped
        ):
            source_file.unlink()
            os.mkfifo(source_file)
            swapped = True
        return original_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", _open_after_swap)

    with pytest.raises(ArtifactTreeCopyError, match="changed during staging"):
        copy_bounded_regular_tree(
            source,
            destination,
            max_entries=8,
            max_total_bytes=32,
        )

    assert swapped is True
    assert not destination.exists()


def test_artifact_staging_enforces_depth_bound(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    current = source
    for index in range(130):
        current /= f"d{index}"
        current.mkdir()
    destination = tmp_path / "destination"

    with pytest.raises(ArtifactTreeCopyError, match="depth limit"):
        copy_bounded_regular_tree(
            source,
            destination,
            max_entries=512,
            max_total_bytes=32,
        )

    assert not destination.exists()


def test_artifact_staging_rejects_regular_file_hardlink_alias(tmp_path: Path) -> None:
    external = tmp_path / "external.txt"
    external.write_text("operator secret", encoding="utf-8")
    source = tmp_path / "source"
    source.mkdir()
    os.link(external, source / "alias.txt")
    destination = tmp_path / "destination"

    with pytest.raises(ArtifactTreeCopyError, match="hard link"):
        copy_bounded_regular_tree(
            source,
            destination,
            max_entries=8,
            max_total_bytes=32,
        )

    assert not destination.exists()


def test_artifact_staging_rechecks_hardlink_count_after_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    source_file = source / "payload.txt"
    source_file.write_bytes(b"approved")
    external_alias = tmp_path / "external-alias.txt"
    destination = tmp_path / "destination"
    original_open = os.open
    linked = False

    def _open_after_link(
        path: str | bytes | Path,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal linked
        if (
            path == "payload.txt"
            and dir_fd is not None
            and flags & (os.O_WRONLY | os.O_RDWR) == 0
            and not linked
        ):
            os.link(source_file, external_alias)
            linked = True
        return original_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", _open_after_link)

    with pytest.raises(ArtifactTreeCopyError, match="hard link"):
        copy_bounded_regular_tree(
            source,
            destination,
            max_entries=8,
            max_total_bytes=32,
        )

    assert linked is True
    assert not destination.exists()


def test_artifact_staging_rejects_changed_mount_identity_for_nested_subtree(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    nested = source / "mounted"
    nested.mkdir()
    (nested / "secret.txt").write_text("operator secret", encoding="utf-8")
    destination = tmp_path / "destination"
    nested_inode = nested.stat().st_ino

    def _changed_mount_id(fd: int) -> int:
        return 200 if os.fstat(fd).st_ino == nested_inode else 100

    monkeypatch.setattr(
        artifact_staging_module,
        "_mount_id",
        _changed_mount_id,
    )

    with pytest.raises(ArtifactTreeCopyError, match="nested mount"):
        copy_bounded_regular_tree(
            source,
            destination,
            max_entries=8,
            max_total_bytes=32,
        )

    assert not destination.exists()


def test_artifact_staging_fails_closed_when_mount_identity_is_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "file.txt").write_text("payload", encoding="utf-8")
    destination = tmp_path / "destination"

    def _mount_id_unavailable(_fd: int) -> int:
        raise ArtifactTreeCopyError("artifact mount identity unavailable")

    monkeypatch.setattr(
        artifact_staging_module,
        "_mount_id",
        _mount_id_unavailable,
    )

    with pytest.raises(ArtifactTreeCopyError, match="mount identity unavailable"):
        copy_bounded_regular_tree(
            source,
            destination,
            max_entries=8,
            max_total_bytes=32,
        )

    assert not destination.exists()


def test_artifact_staging_rejects_source_root_mount_alias(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    destination = tmp_path / "destination"
    source_inode = source.stat().st_ino

    def _source_root_mount_id(fd: int) -> int:
        return 200 if os.fstat(fd).st_ino == source_inode else 100

    monkeypatch.setattr(
        artifact_staging_module,
        "_mount_id",
        _source_root_mount_id,
    )

    with pytest.raises(ArtifactTreeCopyError, match="source root mount"):
        copy_bounded_regular_tree(
            source,
            destination,
            max_entries=8,
            max_total_bytes=32,
        )

    assert not destination.exists()


def test_artifact_staging_rejects_underlying_source_alias_of_destination_ancestry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "bind-alias" / "payload"
    source.mkdir(parents=True)
    (source / "file.txt").write_text("payload", encoding="utf-8")
    destination_parent = tmp_path / "state" / "bundles"
    destination_parent.mkdir(parents=True)
    destination = destination_parent / ".install.tmp"
    source_stat = source.stat()

    monkeypatch.setattr(
        artifact_staging_module,
        "_directory_ancestor_identities",
        lambda _fd: {(source_stat.st_dev, source_stat.st_ino)},
        raising=False,
    )

    with pytest.raises(ArtifactTreeCopyError, match="underlying alias overlap"):
        copy_bounded_regular_tree(
            source,
            destination,
            max_entries=8,
            max_total_bytes=32,
        )

    assert not destination.exists()


def test_artifact_staging_collects_held_destination_ancestor_identities(
    tmp_path: Path,
) -> None:
    destination_parent = tmp_path / "state" / "bundles"
    destination_parent.mkdir(parents=True)
    directory_fd = os.open(
        destination_parent,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
    )
    try:
        identities = artifact_staging_module._directory_ancestor_identities(directory_fd)
    finally:
        os.close(directory_fd)

    expected = {
        (path.stat().st_dev, path.stat().st_ino)
        for path in (destination_parent, destination_parent.parent, tmp_path)
    }
    assert expected <= identities
