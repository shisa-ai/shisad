"""O4C stopped-daemon data-root backup and restore contracts."""

from __future__ import annotations

import json
import os
import stat
import zipfile
from collections.abc import Callable
from pathlib import Path, PurePosixPath

import pytest
from filelock import FileLock

import shisad.core.data_backup as data_backup_module
from shisad.core.data_backup import (
    DataBackupError,
    create_data_backup,
    restore_data_backup,
)


def _representative_root(root: Path) -> dict[str, bytes]:
    files = {
        "sessions/state/session-1.json": b'{"session":"one"}\n',
        "checkpoints/checkpoint-1.json": b'{"checkpoint":"one"}\n',
        "pending_actions.json": b'{"status":"outcome_unknown"}\n',
        "tasks/task-1.json": b'{"schedule":"daily"}\n',
        "memory_entries/memory.sqlite3": b"memory-sqlite-bytes",
        "timeline/timeline.sqlite3": b"timeline-sqlite-bytes",
        "channels/state/replay.sqlite3": b"replay-sqlite-bytes",
        "channels/delivery/outbox.sqlite3": b"outbox-sqlite-bytes",
        "credentials.d/operator.secret": b"secret-material",
        "audit.jsonl": b'{"event_id":"1","hash":"abc"}\n',
    }
    for relative, payload in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
    (root / "empty-owned-directory").mkdir()
    return files


def _payload_paths(root: Path) -> set[str]:
    return {
        path.relative_to(root).as_posix() for path in root.rglob("*") if path.name != ".shisad.lock"
    }


def _rewrite_manifest(
    archive: Path,
    mutate: Callable[[dict[str, object]], None],
) -> None:
    replacement = archive.with_name(f"{archive.name}.replacement")
    with zipfile.ZipFile(archive, "r") as source:
        members = [(info, source.read(info)) for info in source.infolist()]
    manifest = json.loads(
        dict((info.filename, payload) for info, payload in members)["manifest.json"]
    )
    mutate(manifest)
    manifest_bytes = (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()
    with zipfile.ZipFile(replacement, "w") as target:
        for info, payload in members:
            target.writestr(info, manifest_bytes if info.filename == "manifest.json" else payload)
    replacement.replace(archive)


def test_o4c_backup_restore_round_trip_preserves_all_owned_state(tmp_path: Path) -> None:
    source = tmp_path / "source"
    files = _representative_root(source)
    archive = tmp_path / "snapshot.shisad-backup"
    external = tmp_path / "operator-config.toml"
    external.write_text("external=true\n", encoding="utf-8")

    backup = create_data_backup(source, archive)
    restored = tmp_path / "restored"
    restore = restore_data_backup(archive, restored)

    assert backup.verified is True
    assert restore.verified is True
    assert restore.backup_id == backup.backup_id
    assert restore.file_count == len(files)
    assert restore.total_bytes == sum(len(payload) for payload in files.values())
    assert _payload_paths(restored) == _payload_paths(source)
    for relative, payload in files.items():
        assert (restored / relative).read_bytes() == payload
    assert (restored / "empty-owned-directory").is_dir()
    assert external.read_text(encoding="utf-8") == "external=true\n"
    if os.name == "posix":
        assert stat.S_IMODE(archive.stat().st_mode) == 0o600
        assert all(stat.S_IMODE(path.stat().st_mode) & 0o077 == 0 for path in restored.rglob("*"))


def test_o4c_manifest_is_canonical_private_and_excludes_only_root_lock(
    tmp_path: Path,
) -> None:
    source = tmp_path / "operator-private-source"
    files = _representative_root(source)
    (source / ".shisad.lock").write_text("stale lock artifact", encoding="utf-8")
    archive = tmp_path / "snapshot.shisad-backup"

    result = create_data_backup(source, archive)

    with zipfile.ZipFile(archive) as bundle:
        manifest_bytes = bundle.read("manifest.json")
        manifest = json.loads(manifest_bytes)
        names = bundle.namelist()
        assert (
            manifest_bytes
            == (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()
        )
        assert all(info.compress_type == zipfile.ZIP_STORED for info in bundle.infolist())
    assert str(source) not in manifest_bytes.decode()
    assert manifest["format_version"] == 1
    assert manifest["backup_id"] == result.backup_id
    assert len(manifest["source_root_fingerprint"]) == 64
    assert "data/.shisad.lock" not in names
    assert {f"data/{path}" for path in files} <= set(names)
    assert names.count("manifest.json") == 1


def test_o4c_backup_refuses_lock_contention_unsafe_entries_and_destinations(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    _representative_root(source)
    archive = tmp_path / "snapshot.shisad-backup"
    lock = FileLock(str(source / ".shisad.lock"), timeout=0)

    with lock, pytest.raises(DataBackupError, match=r"stopped|lock"):
        create_data_backup(source, archive)
    assert not archive.exists()

    lock_path = source / ".shisad.lock"
    lock_path.unlink(missing_ok=True)
    external_lock = tmp_path / "external-lock"
    external_lock.write_text("do-not-touch", encoding="utf-8")
    lock_path.symlink_to(external_lock)
    with pytest.raises(DataBackupError, match=r"lock|unsafe|symlink"):
        create_data_backup(source, archive)
    assert external_lock.read_text(encoding="utf-8") == "do-not-touch"
    assert not archive.exists()
    lock_path.unlink()

    (source / "unsafe-link").symlink_to(source / "audit.jsonl")
    with pytest.raises(DataBackupError, match=r"symlink|unsafe"):
        create_data_backup(source, archive)
    assert not archive.exists()
    (source / "unsafe-link").unlink()

    archive.write_bytes(b"do-not-overwrite")
    with pytest.raises(DataBackupError, match=r"exists|overwrite"):
        create_data_backup(source, archive)
    assert archive.read_bytes() == b"do-not-overwrite"
    with pytest.raises(DataBackupError, match=r"inside|data root"):
        create_data_backup(source, source / "nested.shisad-backup")


def test_o4c_backup_refuses_traversal_and_entry_inspection_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    _representative_root(source)
    archive = tmp_path / "snapshot.shisad-backup"
    original_walk = os.walk

    def unreadable_walk(
        root: Path,
        *,
        followlinks: bool,
        onerror: Callable[[OSError], None] | None = None,
    ) -> object:
        assert onerror is not None
        onerror(PermissionError("unreadable subtree"))
        return iter(())

    monkeypatch.setattr(os, "walk", unreadable_walk)
    with pytest.raises(DataBackupError, match=r"scan|travers|inspect"):
        create_data_backup(source, archive)
    assert not archive.exists()

    monkeypatch.setattr(os, "walk", original_walk)
    original_lstat = Path.lstat

    def unreadable_lstat(path: Path) -> os.stat_result:
        if path.name == "audit.jsonl":
            raise PermissionError("entry inspection failed")
        return original_lstat(path)

    monkeypatch.setattr(Path, "lstat", unreadable_lstat)
    with pytest.raises(DataBackupError, match=r"scan|travers|inspect"):
        create_data_backup(source, archive)
    assert not archive.exists()


def test_o4c_backup_refuses_source_replacement_while_acquiring_lock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    _representative_root(source)
    displaced = tmp_path / "displaced-source"
    replacement = tmp_path / "replacement-source"
    replacement.mkdir()
    (replacement / "foreign").write_bytes(b"not-source-state")
    archive = tmp_path / "snapshot.shisad-backup"
    original_acquire = FileLock.acquire
    replaced = False

    def replace_source(lock: FileLock, *args: object, **kwargs: object) -> object:
        nonlocal replaced
        if not replaced and Path(lock.lock_file) == source / ".shisad.lock":
            source.rename(displaced)
            source.symlink_to(replacement, target_is_directory=True)
            replaced = True
        return original_acquire(lock, *args, **kwargs)

    monkeypatch.setattr(FileLock, "acquire", replace_source)

    with pytest.raises(DataBackupError, match=r"changed|replaced|unsafe"):
        create_data_backup(source, archive)

    assert not archive.exists()


def test_o4c_restore_verifies_tamper_before_writing(tmp_path: Path) -> None:
    source = tmp_path / "source"
    _representative_root(source)
    archive = tmp_path / "snapshot.shisad-backup"
    create_data_backup(source, archive)
    with (
        pytest.warns(UserWarning, match="Duplicate name"),
        zipfile.ZipFile(archive, "a", compression=zipfile.ZIP_STORED) as bundle,
    ):
        bundle.writestr("data/audit.jsonl", b"tampered")
    destination = tmp_path / "restored"

    with pytest.raises(DataBackupError, match=r"duplicate|manifest|digest"):
        restore_data_backup(archive, destination)

    assert not destination.exists() or _payload_paths(destination) == set()


def test_o4c_restore_rejects_boolean_owner_mode_before_writing(tmp_path: Path) -> None:
    source = tmp_path / "source"
    _representative_root(source)
    archive = tmp_path / "snapshot.shisad-backup"
    create_data_backup(source, archive)

    def set_boolean_mode(manifest: dict[str, object]) -> None:
        entries = manifest["entries"]
        assert isinstance(entries, list)
        entries[0]["mode"] = True

    _rewrite_manifest(archive, set_boolean_mode)
    destination = tmp_path / "restored"

    with pytest.raises(DataBackupError, match=r"metadata|manifest"):
        restore_data_backup(archive, destination)

    assert not destination.exists()


@pytest.mark.parametrize("timestamp", ["2026-08-20T00:00:00", "2026-08-20Z"])
def test_o4c_restore_rejects_non_utc_or_date_only_manifest_timestamp_before_writing(
    tmp_path: Path,
    timestamp: str,
) -> None:
    source = tmp_path / "source"
    _representative_root(source)
    archive = tmp_path / "snapshot.shisad-backup"
    create_data_backup(source, archive)

    def set_naive_timestamp(manifest: dict[str, object]) -> None:
        manifest["created_at"] = timestamp

    _rewrite_manifest(archive, set_naive_timestamp)
    destination = tmp_path / "restored"

    with pytest.raises(DataBackupError, match=r"timestamp|manifest"):
        restore_data_backup(archive, destination)

    assert not destination.exists()


def test_o4c_restore_rejects_missing_parent_directory_record_before_writing(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    _representative_root(source)
    archive = tmp_path / "snapshot.shisad-backup"
    create_data_backup(source, archive)

    def remove_parent(manifest: dict[str, object]) -> None:
        entries = manifest["entries"]
        assert isinstance(entries, list)
        manifest["entries"] = [entry for entry in entries if entry["path"] != "sessions"]

    _rewrite_manifest(archive, remove_parent)
    destination = tmp_path / "restored"

    with pytest.raises(DataBackupError, match=r"structure|parent"):
        restore_data_backup(archive, destination)

    assert not destination.exists()


def test_o4c_restore_rejects_reserved_root_lock_record_before_writing(tmp_path: Path) -> None:
    source = tmp_path / "source"
    _representative_root(source)
    archive = tmp_path / "snapshot.shisad-backup"
    create_data_backup(source, archive)

    def reserve_root_lock(manifest: dict[str, object]) -> None:
        entries = manifest["entries"]
        assert isinstance(entries, list)
        for entry in entries:
            if entry["path"] == "empty-owned-directory":
                entry["path"] = ".shisad.lock"
                break
        entries.sort(key=lambda entry: entry["path"])

    _rewrite_manifest(archive, reserve_root_lock)
    destination = tmp_path / "restored"

    with pytest.raises(DataBackupError, match=r"reserved|manifest"):
        restore_data_backup(archive, destination)

    assert not destination.exists()


def test_o4c_restore_rejects_windows_drive_relative_record_before_writing(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    _representative_root(source)
    archive = tmp_path / "snapshot.shisad-backup"
    create_data_backup(source, archive)

    def set_drive_relative_path(manifest: dict[str, object]) -> None:
        entries = manifest["entries"]
        assert isinstance(entries, list)
        for entry in entries:
            if entry["path"] == "empty-owned-directory":
                entry["path"] = "C:escape"
                break
        entries.sort(key=lambda entry: entry["path"])

    _rewrite_manifest(archive, set_drive_relative_path)

    with pytest.raises(DataBackupError, match=r"path|manifest"):
        restore_data_backup(archive, tmp_path / "restored")

    assert not (tmp_path / "restored").exists()


@pytest.mark.parametrize(
    ("member", "compression"),
    [
        ("data/../escape", zipfile.ZIP_STORED),
        ("data\\escape", zipfile.ZIP_STORED),
        ("data/unexpected", zipfile.ZIP_DEFLATED),
    ],
)
def test_o4c_restore_rejects_unsafe_or_compressed_unexpected_members(
    tmp_path: Path,
    member: str,
    compression: int,
) -> None:
    source = tmp_path / "source"
    _representative_root(source)
    archive = tmp_path / "snapshot.shisad-backup"
    create_data_backup(source, archive)
    with zipfile.ZipFile(archive, "a") as bundle:
        bundle.writestr(member, b"unexpected", compress_type=compression)

    with pytest.raises(DataBackupError, match=r"member|path|compressed|unexpected"):
        restore_data_backup(archive, tmp_path / "restored")

    assert not (tmp_path / "escape").exists()


def test_o4c_restore_refuses_nonempty_or_locked_destination(tmp_path: Path) -> None:
    source = tmp_path / "source"
    _representative_root(source)
    archive = tmp_path / "snapshot.shisad-backup"
    create_data_backup(source, archive)

    nonempty = tmp_path / "nonempty"
    nonempty.mkdir()
    marker = nonempty / "keep"
    marker.write_bytes(b"keep")
    with pytest.raises(DataBackupError, match="empty"):
        restore_data_backup(archive, nonempty)
    assert marker.read_bytes() == b"keep"

    locked = tmp_path / "locked"
    locked.mkdir()
    lock = FileLock(str(locked / ".shisad.lock"), timeout=0)
    with lock, pytest.raises(DataBackupError, match=r"stopped|lock"):
        restore_data_backup(archive, locked)


def test_o4c_restore_retains_an_empty_root_and_normal_lock(tmp_path: Path) -> None:
    source = tmp_path / "empty-source"
    source.mkdir()
    archive = tmp_path / "snapshot.shisad-backup"
    create_data_backup(source, archive)
    destination = tmp_path / "restored"

    result = restore_data_backup(archive, destination)

    assert result.file_count == 0
    assert result.directory_count == 0
    assert destination.is_dir()
    assert (destination / ".shisad.lock").is_file()


def test_o4c_restore_refuses_destination_replacement_while_acquiring_lock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    _representative_root(source)
    archive = tmp_path / "snapshot.shisad-backup"
    create_data_backup(source, archive)
    destination = tmp_path / "restored"
    displaced = tmp_path / "displaced-destination"
    replacement = tmp_path / "replacement-destination"
    replacement.mkdir()
    original_acquire = FileLock.acquire
    replaced = False

    def replace_destination(lock: FileLock, *args: object, **kwargs: object) -> object:
        nonlocal replaced
        if not replaced and Path(lock.lock_file) == destination / ".shisad.lock":
            destination.rename(displaced)
            destination.symlink_to(replacement, target_is_directory=True)
            replaced = True
        return original_acquire(lock, *args, **kwargs)

    monkeypatch.setattr(FileLock, "acquire", replace_destination)

    with pytest.raises(DataBackupError, match=r"changed|replaced|unsafe"):
        restore_data_backup(archive, destination)

    assert not [path for path in replacement.iterdir() if path.name != ".shisad.lock"]


def test_o4c_restore_pins_root_before_acquiring_lock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    _representative_root(source)
    archive = tmp_path / "snapshot.shisad-backup"
    create_data_backup(source, archive)
    destination = tmp_path / "restored"
    original_open_root = data_backup_module._open_restore_root
    original_acquire = FileLock.acquire
    root_opened = False

    def observe_root(path: Path, identity: tuple[int, int]) -> int:
        nonlocal root_opened
        root_opened = True
        return original_open_root(path, identity)

    def require_root_first(lock: FileLock, *args: object, **kwargs: object) -> object:
        assert root_opened
        return original_acquire(lock, *args, **kwargs)

    monkeypatch.setattr(data_backup_module, "_open_restore_root", observe_root)
    monkeypatch.setattr(FileLock, "acquire", require_root_first)

    assert restore_data_backup(archive, destination).verified is True


def test_o4c_restore_open_failure_removes_its_new_empty_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    _representative_root(source)
    archive = tmp_path / "snapshot.shisad-backup"
    create_data_backup(source, archive)
    destination = tmp_path / "restored"

    def fail_open(_path: Path, _identity: tuple[int, int]) -> int:
        raise DataBackupError("injected root-open failure")

    monkeypatch.setattr(data_backup_module, "_open_restore_root", fail_open)

    with pytest.raises(DataBackupError, match=r"root-open failure"):
        restore_data_backup(archive, destination)

    assert not destination.exists()


def test_o4c_restore_never_follows_replaced_intermediate_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    _representative_root(source)
    archive = tmp_path / "snapshot.shisad-backup"
    create_data_backup(source, archive)
    destination = tmp_path / "restored"
    displaced = tmp_path / "displaced-sessions"
    outside = tmp_path / "outside"
    outside.mkdir()
    original_mkdir = os.mkdir
    replaced = False

    def replace_parent(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> None:
        nonlocal replaced
        if not replaced and os.fsdecode(path) in {"sessions/state", "state"}:
            live_parent = destination / "sessions"
            live_parent.rename(displaced)
            live_parent.symlink_to(outside, target_is_directory=True)
            replaced = True
        original_mkdir(path, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "mkdir", replace_parent)

    with pytest.raises(DataBackupError, match=r"restore|unsafe|link|changed"):
        restore_data_backup(archive, destination)

    assert list(outside.iterdir()) == []


def test_o4c_restore_uses_safe_path_fallback_without_directory_fd_support(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    files = _representative_root(source)
    archive = tmp_path / "snapshot.shisad-backup"
    create_data_backup(source, archive)
    destination = tmp_path / "restored"
    original_open = os.open

    def windows_style_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        if flags & int(getattr(os, "O_DIRECTORY", 0)) or dir_fd is not None:
            raise NotImplementedError("directory descriptors unavailable")
        return original_open(path, flags, mode)

    monkeypatch.setattr(os, "supports_dir_fd", set())
    monkeypatch.setattr(os, "open", windows_style_open)

    result = restore_data_backup(archive, destination)

    assert result.verified is True
    assert {path: (destination / path).read_bytes() for path in files} == files


def test_o4c_restore_rejects_archive_symlink_without_nofollow_flag(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    _representative_root(source)
    archive = tmp_path / "snapshot.shisad-backup"
    create_data_backup(source, archive)
    archive_link = tmp_path / "snapshot-link.shisad-backup"
    archive_link.symlink_to(archive)
    monkeypatch.setattr(data_backup_module, "hardened_open_flags", lambda flags: flags)

    with pytest.raises(DataBackupError, match=r"archive|symlink|regular"):
        restore_data_backup(archive_link, tmp_path / "restored")

    assert not (tmp_path / "restored").exists()


def test_o4c_restore_reads_archive_through_one_open_descriptor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    _representative_root(source)
    archive = tmp_path / "snapshot.shisad-backup"
    create_data_backup(source, archive)
    original_zip_file = zipfile.ZipFile

    def descriptor_zip_file(file: object, *args: object, **kwargs: object) -> zipfile.ZipFile:
        mode = args[0] if args else kwargs.get("mode", "r")
        if mode == "r":
            assert hasattr(file, "read") and not isinstance(file, (str, os.PathLike))
        return original_zip_file(file, *args, **kwargs)

    monkeypatch.setattr(zipfile, "ZipFile", descriptor_zip_file)

    result = restore_data_backup(archive, tmp_path / "restored")

    assert result.verified is True


@pytest.mark.parametrize("failure", [OSError("I/O interruption"), RuntimeError("helper failed")])
def test_o4c_restore_failure_cleans_created_payload(
    tmp_path: Path,
    failure: Exception,
) -> None:
    source = tmp_path / "source"
    _representative_root(source)
    archive = tmp_path / "snapshot.shisad-backup"
    create_data_backup(source, archive)
    destination = tmp_path / "restored"
    calls: list[PurePosixPath] = []

    def fail_after_first_file(relative: PurePosixPath) -> None:
        calls.append(relative)
        if len(calls) == 2:
            raise failure

    with pytest.raises(DataBackupError, match=r"restore|interruption|helper"):
        restore_data_backup(archive, destination, fault_injector=fail_after_first_file)

    assert calls
    assert not destination.exists() or _payload_paths(destination) == set()


def test_o4c_restore_reopens_restricted_directories_before_failure_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    _representative_root(source)
    archive = tmp_path / "snapshot.shisad-backup"
    create_data_backup(source, archive)
    destination = tmp_path / "restored"
    original_tighten = data_backup_module._tighten_descriptor
    original_chmod = os.chmod
    calls = 0

    def fail_after_restricting_child(descriptor: int, mode: int) -> str:
        nonlocal calls
        calls += 1
        if calls == 12:
            os.fchmod(descriptor, 0)
            return "supported"
        if calls == 13:
            return "failed"
        return original_tighten(descriptor, mode)

    monkeypatch.setattr(data_backup_module, "_tighten_descriptor", fail_after_restricting_child)

    def unsupported_nofollow_chmod(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        mode: int,
        *,
        dir_fd: int | None = None,
        follow_symlinks: bool = True,
    ) -> None:
        if dir_fd is not None and not follow_symlinks:
            raise ValueError("fchmodat nofollow unavailable")
        original_chmod(path, mode, dir_fd=dir_fd, follow_symlinks=follow_symlinks)

    monkeypatch.setattr(os, "chmod", unsupported_nofollow_chmod)

    try:
        with pytest.raises(DataBackupError, match=r"permission|restore"):
            restore_data_backup(archive, destination)
        assert not destination.exists() or _payload_paths(destination) == set()
    finally:
        for restricted in (destination / "channels" / "delivery",):
            if restricted.exists():
                os.chmod(restricted, 0o700)


def test_o4c_backup_refuses_if_published_inode_was_not_verified(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    _representative_root(source)
    archive = tmp_path / "snapshot.shisad-backup"
    original_link = os.link

    def replace_before_link(
        source_path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        destination_path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        **kwargs: object,
    ) -> None:
        temporary = Path(source_path)
        temporary.unlink()
        temporary.write_bytes(b"unverified replacement")
        original_link(source_path, destination_path, **kwargs)

    monkeypatch.setattr(os, "link", replace_before_link)

    with pytest.raises(DataBackupError, match=r"publish|verified|changed"):
        create_data_backup(source, archive)

    assert not archive.exists()
