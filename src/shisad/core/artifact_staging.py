"""Bounded no-follow copies for caller-controlled artifact trees."""

from __future__ import annotations

import errno
import os
import shutil
import stat
from dataclasses import dataclass
from pathlib import Path

_COPY_BUFFER_BYTES = 1024 * 1024
_MAX_TREE_DEPTH = 128
DEFAULT_ARTIFACT_STAGE_MAX_ENTRIES = 4096
DEFAULT_ARTIFACT_STAGE_MAX_BYTES = 64 * 1024 * 1024


class ArtifactTreeCopyError(OSError):
    """An artifact source tree is unsafe or exceeds its staging budget."""


@dataclass(frozen=True, slots=True)
class ArtifactTreeCopyResult:
    """Finite copy totals for validation evidence and callers."""

    entry_count: int
    file_count: int
    total_bytes: int


@dataclass(slots=True)
class _CopyTotals:
    entry_count: int = 0
    file_count: int = 0
    total_bytes: int = 0


def _absolute_path(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _directory_open_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )


def _open_directory_chain(path: Path) -> int:
    """Open an existing absolute directory chain without following links."""

    absolute = _absolute_path(path)
    current_fd = os.open(absolute.anchor, _directory_open_flags())
    try:
        for component in absolute.parts[1:]:
            try:
                next_fd = os.open(component, _directory_open_flags(), dir_fd=current_fd)
            except OSError as exc:
                if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
                    raise ArtifactTreeCopyError(
                        f"artifact tree directory ancestry contains a symlink: {absolute}"
                    ) from exc
                raise
            os.close(current_fd)
            current_fd = next_fd
        return current_fd
    except BaseException:
        os.close(current_fd)
        raise


def fsync_directory(path: Path) -> None:
    """Durably publish directory-entry changes through a no-follow descriptor."""

    directory_fd = _open_directory_chain(path)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _same_inode(left: os.stat_result, right: os.stat_result) -> bool:
    return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)


def _mount_id(fd: int) -> int:
    """Read the kernel mount identity for one held Linux file descriptor."""

    try:
        fdinfo = Path(f"/proc/self/fdinfo/{fd}").read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ArtifactTreeCopyError("artifact mount identity unavailable") from exc
    for line in fdinfo.splitlines():
        key, separator, value = line.partition(":")
        if key == "mnt_id" and separator:
            try:
                return int(value.strip())
            except ValueError as exc:
                raise ArtifactTreeCopyError("artifact mount identity unavailable") from exc
    raise ArtifactTreeCopyError("artifact mount identity unavailable")


def _paths_overlap(source: Path, destination: Path) -> bool:
    return source == destination or source in destination.parents or destination in source.parents


def _copy_file(
    *,
    source_parent_fd: int,
    destination_parent_fd: int,
    name: str,
    observed: os.stat_result,
    totals: _CopyTotals,
    max_total_bytes: int,
    root_device: int,
    root_mount_id: int,
) -> None:
    if observed.st_dev != root_device:
        raise ArtifactTreeCopyError(f"artifact tree contains a mounted file: {name}")
    if observed.st_nlink != 1:
        raise ArtifactTreeCopyError(f"artifact tree contains a hard link: {name}")
    if totals.total_bytes + observed.st_size > max_total_bytes:
        raise ArtifactTreeCopyError("artifact tree byte limit exceeded")
    source_fd = os.open(
        name,
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0),
        dir_fd=source_parent_fd,
    )
    destination_fd = -1
    try:
        opened = os.fstat(source_fd)
        if not stat.S_ISREG(opened.st_mode) or not _same_inode(observed, opened):
            raise ArtifactTreeCopyError(f"artifact tree entry changed during staging: {name}")
        if opened.st_nlink != 1:
            raise ArtifactTreeCopyError(f"artifact tree contains a hard link: {name}")
        if _mount_id(source_fd) != root_mount_id:
            raise ArtifactTreeCopyError(f"artifact tree contains a nested mount: {name}")
        destination_fd = os.open(
            name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=destination_parent_fd,
        )
        copied = 0
        while True:
            chunk = os.read(source_fd, _COPY_BUFFER_BYTES)
            if not chunk:
                break
            if totals.total_bytes + copied + len(chunk) > max_total_bytes:
                raise ArtifactTreeCopyError("artifact tree byte limit exceeded")
            view = memoryview(chunk)
            while view:
                written = os.write(destination_fd, view)
                if written <= 0:
                    raise ArtifactTreeCopyError(f"artifact staging write stalled: {name}")
                view = view[written:]
            copied += len(chunk)
        os.fchmod(destination_fd, 0o600)
        os.fsync(destination_fd)
        totals.file_count += 1
        totals.total_bytes += copied
    finally:
        if destination_fd >= 0:
            os.close(destination_fd)
        os.close(source_fd)


def _copy_directory_contents(
    *,
    source_fd: int,
    destination_fd: int,
    totals: _CopyTotals,
    max_entries: int,
    max_total_bytes: int,
    root_device: int,
    root_mount_id: int,
    depth: int = 0,
) -> None:
    if depth > _MAX_TREE_DEPTH:
        raise ArtifactTreeCopyError("artifact tree depth limit exceeded")
    with os.scandir(source_fd) as entries:
        for entry in entries:
            name = entry.name
            observed = entry.stat(follow_symlinks=False)
            totals.entry_count += 1
            if totals.entry_count > max_entries:
                raise ArtifactTreeCopyError("artifact tree entry limit exceeded")
            if stat.S_ISLNK(observed.st_mode):
                raise ArtifactTreeCopyError(f"artifact tree contains a symlink: {name}")
            if stat.S_ISREG(observed.st_mode):
                _copy_file(
                    source_parent_fd=source_fd,
                    destination_parent_fd=destination_fd,
                    name=name,
                    observed=observed,
                    totals=totals,
                    max_total_bytes=max_total_bytes,
                    root_device=root_device,
                    root_mount_id=root_mount_id,
                )
                continue
            if not stat.S_ISDIR(observed.st_mode):
                raise ArtifactTreeCopyError(
                    f"artifact tree must contain only regular files and directories: {name}"
                )
            if observed.st_dev != root_device:
                raise ArtifactTreeCopyError(f"artifact tree contains a nested mount: {name}")
            source_child_fd = os.open(name, _directory_open_flags(), dir_fd=source_fd)
            destination_child_fd = -1
            try:
                opened = os.fstat(source_child_fd)
                if not stat.S_ISDIR(opened.st_mode) or not _same_inode(observed, opened):
                    raise ArtifactTreeCopyError(
                        f"artifact tree directory changed during staging: {name}"
                    )
                if _mount_id(source_child_fd) != root_mount_id:
                    raise ArtifactTreeCopyError(f"artifact tree contains a nested mount: {name}")
                os.mkdir(name, 0o700, dir_fd=destination_fd)
                destination_child_fd = os.open(
                    name,
                    _directory_open_flags(),
                    dir_fd=destination_fd,
                )
                os.fchmod(destination_child_fd, 0o700)
                _copy_directory_contents(
                    source_fd=source_child_fd,
                    destination_fd=destination_child_fd,
                    totals=totals,
                    max_entries=max_entries,
                    max_total_bytes=max_total_bytes,
                    root_device=root_device,
                    root_mount_id=root_mount_id,
                    depth=depth + 1,
                )
                os.fsync(destination_child_fd)
            finally:
                if destination_child_fd >= 0:
                    os.close(destination_child_fd)
                os.close(source_child_fd)
    os.fsync(destination_fd)


def copy_bounded_regular_tree(
    source: Path,
    destination: Path,
    *,
    max_entries: int,
    max_total_bytes: int,
) -> ArtifactTreeCopyResult:
    """Copy one tree without links, special files, overlap, or unbounded input."""

    if max_entries < 1 or max_total_bytes < 1:
        raise ValueError("artifact staging bounds must be positive")
    source = _absolute_path(source)
    destination = _absolute_path(destination)
    if _paths_overlap(source, destination):
        raise ArtifactTreeCopyError("artifact source and destination overlap")

    source_fd = _open_directory_chain(source)
    source_parent_fd = -1
    destination_parent_fd = -1
    destination_fd = -1
    created = False
    try:
        source_stat = os.fstat(source_fd)
        source_mount_id = _mount_id(source_fd)
        source_parent_fd = _open_directory_chain(source.parent)
        if _mount_id(source_parent_fd) != source_mount_id:
            raise ArtifactTreeCopyError("artifact source root mount alias is not allowed")
        destination_parent_fd = _open_directory_chain(destination.parent)
        os.mkdir(destination.name, 0o700, dir_fd=destination_parent_fd)
        created = True
        destination_fd = os.open(
            destination.name,
            _directory_open_flags(),
            dir_fd=destination_parent_fd,
        )
        os.fchmod(destination_fd, 0o700)
        totals = _CopyTotals()
        _copy_directory_contents(
            source_fd=source_fd,
            destination_fd=destination_fd,
            totals=totals,
            max_entries=max_entries,
            max_total_bytes=max_total_bytes,
            root_device=source_stat.st_dev,
            root_mount_id=source_mount_id,
        )
        os.fsync(destination_parent_fd)
        return ArtifactTreeCopyResult(
            entry_count=totals.entry_count,
            file_count=totals.file_count,
            total_bytes=totals.total_bytes,
        )
    except BaseException:
        if destination_fd >= 0:
            os.close(destination_fd)
            destination_fd = -1
        if created:
            shutil.rmtree(destination, ignore_errors=True)
        raise
    finally:
        if destination_fd >= 0:
            os.close(destination_fd)
        if destination_parent_fd >= 0:
            os.close(destination_parent_fd)
        if source_parent_fd >= 0:
            os.close(source_parent_fd)
        os.close(source_fd)
