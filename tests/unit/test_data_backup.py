"""O4C stopped-daemon data-root backup and restore contracts."""

from __future__ import annotations

import hashlib
import io
import json
import os
import stat
import zipfile
from collections.abc import Callable
from contextlib import suppress
from pathlib import Path, PurePosixPath

import pytest
from filelock import FileLock

import shisad.core.data_backup as data_backup_module
import shisad.core.data_root_handle as data_root_handle_module
from shisad.core.data_backup import (
    DataBackupError,
    create_data_backup,
    restore_data_backup,
)
from shisad.core.data_root_handle import RootHandleError, RootHandleNotFound
from shisad.core.data_root_lock import RootedFileLock


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
    original_listdir = data_root_handle_module._PosixRootHandle.listdir

    def unreadable_listdir(
        _root: data_root_handle_module._PosixRootHandle,
        _relative: PurePosixPath = data_root_handle_module._ROOT,
    ) -> tuple[str, ...]:
        raise data_root_handle_module.RootHandleError("unreadable subtree")

    monkeypatch.setattr(data_root_handle_module._PosixRootHandle, "listdir", unreadable_listdir)
    with pytest.raises(DataBackupError, match=r"scan|travers|inspect"):
        create_data_backup(source, archive)
    assert not archive.exists()

    monkeypatch.setattr(data_root_handle_module._PosixRootHandle, "listdir", original_listdir)
    original_metadata = data_root_handle_module._PosixRootHandle.metadata

    def unreadable_metadata(
        root: data_root_handle_module._PosixRootHandle,
        relative: PurePosixPath,
    ) -> data_root_handle_module.EntryMetadata:
        if relative.name == "audit.jsonl":
            raise data_root_handle_module.RootHandleError("entry inspection failed")
        return original_metadata(root, relative)

    monkeypatch.setattr(data_root_handle_module._PosixRootHandle, "metadata", unreadable_metadata)
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
    original_acquire = RootedFileLock.acquire
    replaced = False

    def replace_source(lock: RootedFileLock, *args: object, **kwargs: object) -> object:
        nonlocal replaced
        if not replaced and Path(lock.lock_file) == source / ".shisad.lock":
            source.rename(displaced)
            source.symlink_to(replacement, target_is_directory=True)
            replaced = True
        return original_acquire(lock, *args, **kwargs)

    monkeypatch.setattr(RootedFileLock, "acquire", replace_source)

    with pytest.raises(DataBackupError, match=r"changed|replaced|unsafe"):
        create_data_backup(source, archive)

    assert not archive.exists()


def test_o4cp_backup_pins_source_root_before_acquiring_lock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    _representative_root(source)
    archive = tmp_path / "snapshot.shisad-backup"
    original_open_root = data_backup_module.open_root
    original_acquire = RootedFileLock.acquire
    source_opened = False

    def observe_root(path: Path, *args: object, **kwargs: object) -> object:
        nonlocal source_opened
        if path == source:
            source_opened = True
        return original_open_root(path, *args, **kwargs)

    def require_source_first(lock: RootedFileLock, *args: object, **kwargs: object) -> object:
        if Path(lock.lock_file) == source / ".shisad.lock":
            assert source_opened
        return original_acquire(lock, *args, **kwargs)

    monkeypatch.setattr(data_backup_module, "open_root", observe_root)
    monkeypatch.setattr(RootedFileLock, "acquire", require_source_first)

    assert create_data_backup(source, archive).verified is True


def test_drh1_backup_binds_the_validated_source_identity_to_root_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    _representative_root(source)
    archive = tmp_path / "snapshot.shisad-backup"
    source_identity = (source.stat().st_dev, source.stat().st_ino)
    original_open_root = data_backup_module.open_root
    observed = False

    def observe_identity(
        path: Path,
        *,
        expected_identity: tuple[int, int] | None = None,
    ) -> object:
        nonlocal observed
        if path == source:
            assert expected_identity == source_identity
            observed = True
        return original_open_root(path, expected_identity=expected_identity)

    monkeypatch.setattr(data_backup_module, "open_root", observe_identity)

    assert create_data_backup(source, archive).verified is True
    assert observed


def test_o4cp_backup_never_follows_replaced_source_intermediate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    _representative_root(source)
    archive = tmp_path / "snapshot.shisad-backup"
    displaced = tmp_path / "displaced-sessions"
    original_open_file = data_root_handle_module._PosixRootHandle.open_file
    replaced = False

    def replace_before_open(
        root: data_root_handle_module._PosixRootHandle,
        relative: PurePosixPath,
        flags: int,
        *,
        expected_identity: tuple[int, int] | None = None,
        for_publication: bool = False,
    ) -> int:
        nonlocal replaced
        if (
            not replaced
            and root.path == source / "sessions" / "state"
            and relative == PurePosixPath("session-1.json")
        ):
            (source / "sessions" / "state" / "session-1.json").rename(displaced)
            (source / "sessions" / "state" / "session-1.json").symlink_to(displaced)
            replaced = True
        return original_open_file(
            root,
            relative,
            flags,
            expected_identity=expected_identity,
            for_publication=for_publication,
        )

    monkeypatch.setattr(data_root_handle_module._PosixRootHandle, "open_file", replace_before_open)

    with pytest.raises(DataBackupError, match=r"source|unsafe|link|changed"):
        create_data_backup(source, archive)

    assert not archive.exists()


def test_drh1_backup_walks_nested_state_through_live_child_handles(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    _representative_root(source)
    archive = tmp_path / "snapshot.shisad-backup"
    displaced = tmp_path / "displaced-sessions"
    replacement = tmp_path / "replacement-sessions"
    replacement.mkdir()
    (replacement / "foreign.json").write_bytes(b"foreign-state")
    original_open_child = data_root_handle_module._PosixRootHandle.open_child_directory
    replaced = False

    def replace_after_open(
        root: data_root_handle_module._PosixRootHandle,
        relative: PurePosixPath,
        *,
        expected_identity: tuple[int, int] | None = None,
    ) -> data_root_handle_module._PosixRootHandle:
        nonlocal replaced
        child = original_open_child(root, relative, expected_identity=expected_identity)
        if root.path == source and relative == PurePosixPath("sessions") and not replaced:
            (source / "sessions").rename(displaced)
            (source / "sessions").symlink_to(replacement, target_is_directory=True)
            replaced = True
        return child

    monkeypatch.setattr(
        data_root_handle_module._PosixRootHandle,
        "open_child_directory",
        replace_after_open,
    )

    with suppress(DataBackupError):
        create_data_backup(source, archive)

    assert replaced
    if archive.exists():
        with zipfile.ZipFile(archive) as bundle:
            assert bundle.read("data/sessions/state/session-1.json") == b'{"session":"one"}\n'
            assert "data/sessions/foreign.json" not in bundle.namelist()


def test_drh1_backup_refuses_publication_parent_path_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    _representative_root(source)
    publication_parent = tmp_path / "archives"
    publication_parent.mkdir()
    displaced = tmp_path / "displaced-archives"
    destination = publication_parent / "snapshot.shisad-backup"
    original_open_root = data_backup_module.open_root
    replaced = False

    def replace_after_open(path: Path, *args: object, **kwargs: object) -> object:
        nonlocal replaced
        root = original_open_root(path, *args, **kwargs)
        if path == publication_parent and not replaced:
            publication_parent.rename(displaced)
            publication_parent.mkdir()
            replaced = True
        return root

    monkeypatch.setattr(data_backup_module, "open_root", replace_after_open)

    with pytest.raises(DataBackupError, match=r"parent|changed|replaced|safely"):
        create_data_backup(source, destination)

    assert replaced
    assert list(publication_parent.iterdir()) == []
    assert not (displaced / destination.name).exists()


def test_drh1_backup_projects_source_fingerprint_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    _representative_root(source)
    destination = tmp_path / "snapshot.shisad-backup"
    original_resolve = Path.resolve

    def fail_source_resolve(path: Path, *args: object, **kwargs: object) -> Path:
        if path == source:
            raise OSError("fingerprint path unavailable")
        return original_resolve(path, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", fail_source_resolve)

    with pytest.raises(DataBackupError, match=r"source|inspect|fingerprint"):
        create_data_backup(source, destination)

    assert not destination.exists()


def test_drh1_backup_pins_parent_before_final_destination_inspection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "data"
    source.mkdir()
    (source / "state.json").write_bytes(b"state")
    archive = tmp_path / "archives" / "snapshot.shisad-backup"
    archive.parent.mkdir()
    original_resolve = Path.resolve

    def reject_final_destination_resolve(path: Path, *, strict: bool = False) -> Path:
        if path == archive:
            pytest.fail("final archive child inspected before its parent was pinned")
        return original_resolve(path, strict=strict)

    monkeypatch.setattr(Path, "resolve", reject_final_destination_resolve)

    result = create_data_backup(source, archive)

    assert result.destination == archive


def test_drh1_backup_source_file_uses_backend_descriptor_identity(tmp_path: Path) -> None:
    source_path = tmp_path / "state.json"
    source_path.write_bytes(b"native-identity")
    native_identity = (91, 92)
    mode = stat.S_IMODE(source_path.stat().st_mode) & 0o700
    entry_metadata = data_root_handle_module.EntryMetadata(
        native_identity,
        mode,
        source_path.stat().st_size,
        source_path.stat().st_mtime_ns,
        False,
    )

    class NativeIdentityRoot:
        def open_file(
            self,
            _name: PurePosixPath,
            _flags: int,
            *,
            expected_identity: tuple[int, int] | None = None,
        ) -> int:
            assert expected_identity == native_identity
            return os.open(source_path, os.O_RDONLY)

        def descriptor_identity(self, _descriptor: int) -> tuple[int, int]:
            return native_identity

        def metadata(self, _name: PurePosixPath) -> object:
            return entry_metadata

    target = io.BytesIO()
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_STORED) as bundle:
        entry = data_backup_module._write_source_file(
            bundle,
            NativeIdentityRoot(),  # type: ignore[arg-type]
            PurePosixPath("state.json"),
            PurePosixPath("state.json"),
            entry_metadata,
        )

    assert entry.sha256 == hashlib.sha256(b"native-identity").hexdigest()


def test_drh1_posix_backup_failure_reports_retained_temporary_residue(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if os.name != "posix":
        pytest.skip("POSIX residue contract")
    source = tmp_path / "data"
    source.mkdir()
    (source / "state.json").write_bytes(b"state")
    archive = tmp_path / "snapshot.shisad-backup"

    def fail_source_walk(*_args: object, **_kwargs: object) -> None:
        raise OSError("injected source walk failure")

    monkeypatch.setattr(data_backup_module, "_write_source_tree", fail_source_walk)

    with pytest.raises(DataBackupError, match=r"retained|residue"):
        create_data_backup(source, archive)

    assert list(tmp_path.glob(f".{archive.name}.*.tmp"))


@pytest.mark.skipif(os.name != "posix", reason="atomic cleanup identity injection")
def test_drh1_atomic_backup_cleanup_refuses_a_replacement_temporary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "data"
    source.mkdir()
    (source / "state.json").write_bytes(b"state")
    archive = tmp_path / "snapshot.shisad-backup"
    original_unlink = data_root_handle_module._PosixRootHandle.unlink
    cleanup_identities: list[tuple[int, int] | None] = []

    monkeypatch.setattr(
        data_root_handle_module._PosixRootHandle,
        "supports_atomic_cleanup",
        property(lambda _root: True),
    )

    def fail_source_walk(*_args: object, **_kwargs: object) -> None:
        raise OSError("injected source walk failure")

    def replace_before_cleanup(
        root: data_root_handle_module._PosixRootHandle,
        relative: PurePosixPath,
        *,
        expected_identity: tuple[int, int] | None = None,
    ) -> None:
        if relative.name.endswith(".tmp"):
            cleanup_identities.append(expected_identity)
            temporary = root.path / relative.name
            temporary.rename(root.path / f"{relative.name}.original")
            temporary.write_bytes(b"replacement")
        original_unlink(root, relative, expected_identity=expected_identity)

    monkeypatch.setattr(data_backup_module, "_write_source_tree", fail_source_walk)
    monkeypatch.setattr(
        data_root_handle_module._PosixRootHandle,
        "unlink",
        replace_before_cleanup,
    )

    with pytest.raises(DataBackupError, match="source walk failure") as caught:
        create_data_backup(source, archive)

    replacements = list(tmp_path.glob(f".{archive.name}.*.tmp"))
    assert cleanup_identities and cleanup_identities[0] is not None
    assert len(replacements) == 1
    assert replacements[0].read_bytes() == b"replacement"
    assert "retained" in str(caught.value) or "residue" in str(caught.value)


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
    original_acquire = RootedFileLock.acquire
    replaced = False

    def replace_destination(lock: RootedFileLock, *args: object, **kwargs: object) -> object:
        nonlocal replaced
        if not replaced and Path(lock.lock_file) == destination / ".shisad.lock":
            destination.rename(displaced)
            destination.symlink_to(replacement, target_is_directory=True)
            replaced = True
        return original_acquire(lock, *args, **kwargs)

    monkeypatch.setattr(RootedFileLock, "acquire", replace_destination)

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
    original_open_child = data_root_handle_module._PosixRootHandle.open_child_directory
    original_acquire = RootedFileLock.acquire
    root_opened = False

    def observe_root(
        root: data_root_handle_module._PosixRootHandle,
        relative: PurePosixPath,
        *,
        expected_identity: tuple[int, int] | None = None,
    ) -> data_root_handle_module._PosixRootHandle:
        nonlocal root_opened
        child = original_open_child(root, relative, expected_identity=expected_identity)
        if relative == PurePosixPath(destination.name):
            root_opened = True
        return child

    def require_root_first(lock: RootedFileLock, *args: object, **kwargs: object) -> object:
        assert root_opened
        return original_acquire(lock, *args, **kwargs)

    monkeypatch.setattr(
        data_root_handle_module._PosixRootHandle, "open_child_directory", observe_root
    )
    monkeypatch.setattr(RootedFileLock, "acquire", require_root_first)

    assert restore_data_backup(archive, destination).verified is True


def test_drh1_restore_open_failure_retains_its_new_empty_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    _representative_root(source)
    archive = tmp_path / "snapshot.shisad-backup"
    create_data_backup(source, archive)
    destination = tmp_path / "restored"

    original_open_child = data_root_handle_module._PosixRootHandle.open_child_directory
    attempts = 0

    def fail_created_root_open(
        root: data_root_handle_module._PosixRootHandle,
        relative: PurePosixPath,
        *,
        expected_identity: tuple[int, int] | None = None,
    ) -> data_root_handle_module._PosixRootHandle:
        nonlocal attempts
        if relative == PurePosixPath(destination.name):
            attempts += 1
            if attempts == 2:
                raise RootHandleError("injected root-open failure")
        return original_open_child(root, relative, expected_identity=expected_identity)

    monkeypatch.setattr(
        data_root_handle_module._PosixRootHandle,
        "open_child_directory",
        fail_created_root_open,
    )

    with pytest.raises(
        DataBackupError,
        match=rf"partial destination retained at {destination}",
    ):
        restore_data_backup(archive, destination)

    assert destination.is_dir()


def test_drh1_prepare_restore_root_closes_handle_when_initial_listdir_fails() -> None:
    class FailingRoot:
        closed = 0

        def listdir(self) -> tuple[str, ...]:
            raise RootHandleError("injected enumeration failure")

        def close(self) -> None:
            self.closed += 1

    root = FailingRoot()

    class PublicationRoot:
        def open_child_directory(self, _destination: PurePosixPath) -> FailingRoot:
            return root

    with pytest.raises(RootHandleError, match="enumeration failure"):
        data_backup_module._prepare_restore_root(  # type: ignore[arg-type]
            PublicationRoot(),
            PurePosixPath("restored"),
        )

    assert root.closed == 1


def test_drh1_prepare_restore_root_removes_created_atomic_root_when_open_fails(
    tmp_path: Path,
) -> None:
    identity = (7, 11)

    class PublicationRoot:
        supports_atomic_cleanup = True

        def __init__(self) -> None:
            self.path = tmp_path
            self.open_attempts = 0
            self.removed: list[tuple[PurePosixPath, tuple[int, int] | None]] = []

        def open_child_directory(
            self,
            _destination: PurePosixPath,
            *,
            expected_identity: tuple[int, int] | None = None,
        ) -> object:
            self.open_attempts += 1
            if self.open_attempts == 1:
                raise RootHandleNotFound("missing")
            assert expected_identity == identity
            raise RootHandleError("injected created-root open failure")

        def create_directory(self, _destination: PurePosixPath, _mode: int) -> tuple[int, int]:
            return identity

        def rmdir(
            self,
            destination: PurePosixPath,
            *,
            expected_identity: tuple[int, int] | None = None,
        ) -> None:
            self.removed.append((destination, expected_identity))

    publication_root = PublicationRoot()

    with pytest.raises(DataBackupError, match="created safely") as caught:
        data_backup_module._prepare_restore_root(  # type: ignore[arg-type]
            publication_root,
            PurePosixPath("restored"),
        )

    assert publication_root.removed == [(PurePosixPath("restored"), identity)]
    assert "retained" not in str(caught.value)


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


@pytest.mark.skipif(os.name != "posix", reason="POSIX descriptor binding contract")
def test_drh1_restore_writes_nested_state_through_live_parent_handles(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    _representative_root(source)
    archive = tmp_path / "snapshot.shisad-backup"
    create_data_backup(source, archive)
    restore_parent = tmp_path / "restore-parent"
    restore_parent.mkdir()
    destination = restore_parent / "restored"
    displaced = tmp_path / "displaced-sessions"
    outside = tmp_path / "outside"
    outside.mkdir()
    original_open_child = data_root_handle_module._PosixRootHandle.open_child_directory
    replaced = False

    def replace_after_open(
        root: data_root_handle_module._PosixRootHandle,
        relative: PurePosixPath,
        *,
        expected_identity: tuple[int, int] | None = None,
    ) -> data_root_handle_module._PosixRootHandle:
        nonlocal replaced
        child = original_open_child(root, relative, expected_identity=expected_identity)
        if root.path == destination and relative == PurePosixPath("sessions") and not replaced:
            (destination / "sessions").rename(displaced)
            (destination / "sessions").symlink_to(outside, target_is_directory=True)
            replaced = True
        return child

    monkeypatch.setattr(
        data_root_handle_module._PosixRootHandle,
        "open_child_directory",
        replace_after_open,
    )

    with pytest.raises(DataBackupError, match=r"changed|replaced|restore|retained"):
        restore_data_backup(archive, destination)

    assert replaced
    assert list(outside.iterdir()) == []
    assert (displaced / "state" / "session-1.json").read_bytes() == b'{"session":"one"}\n'


def test_drh1_restore_refuses_destination_parent_path_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    _representative_root(source)
    archive = tmp_path / "snapshot.shisad-backup"
    create_data_backup(source, archive)
    restore_parent = tmp_path / "restore-parent"
    restore_parent.mkdir()
    displaced = tmp_path / "displaced-restore-parent"
    destination = restore_parent / "restored"
    original_open_root = data_backup_module.open_root
    replaced = False

    def replace_after_open(path: Path, *args: object, **kwargs: object) -> object:
        nonlocal replaced
        root = original_open_root(path, *args, **kwargs)
        if path == restore_parent and not replaced:
            restore_parent.rename(displaced)
            restore_parent.mkdir()
            replaced = True
        return root

    monkeypatch.setattr(data_backup_module, "open_root", replace_after_open)

    with pytest.raises(DataBackupError, match=r"parent|changed|replaced|retained"):
        restore_data_backup(archive, destination)

    assert replaced
    assert list(restore_parent.iterdir()) == []
    assert not (displaced / "restored").exists()


def test_o4cp_restore_refuses_without_root_relative_capability(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    _representative_root(source)
    archive = tmp_path / "snapshot.shisad-backup"
    create_data_backup(source, archive)
    destination = tmp_path / "restored"
    monkeypatch.setattr(os, "supports_dir_fd", set())

    with pytest.raises(DataBackupError, match=r"root-relative|unavailable"):
        restore_data_backup(archive, destination)

    assert not destination.exists()


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
def test_drh1_posix_restore_failure_retains_actionable_residue(
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

    with pytest.raises(
        DataBackupError,
        match=r"restore|interruption|helper|retained|residue",
    ) as caught:
        restore_data_backup(archive, destination, fault_injector=fail_after_first_file)

    assert calls
    if os.name == "posix":
        assert destination.exists()
        assert _payload_paths(destination)
        assert "retained" in str(caught.value) or "residue" in str(caught.value)
    else:
        assert not destination.exists() or _payload_paths(destination) == set()


@pytest.mark.skipif(os.name != "posix", reason="atomic cleanup ledger injection")
def test_drh1_atomic_restore_cleanup_removes_completed_nested_subtrees(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    (source / "a-nested").mkdir(parents=True)
    (source / "a-nested" / "state.json").write_bytes(b"nested")
    (source / "z-later.json").write_bytes(b"later")
    archive = tmp_path / "snapshot.shisad-backup"
    create_data_backup(source, archive)
    destination = tmp_path / "restored"

    monkeypatch.setattr(
        data_root_handle_module._PosixRootHandle,
        "supports_atomic_cleanup",
        property(lambda _root: True),
    )

    def fail_later_sibling(relative: PurePosixPath) -> None:
        if relative == PurePosixPath("z-later.json"):
            raise OSError("injected later sibling failure")

    with pytest.raises(DataBackupError, match="later sibling failure"):
        restore_data_backup(archive, destination, fault_injector=fail_later_sibling)

    assert not destination.exists()


@pytest.mark.skipif(os.name != "posix", reason="atomic cleanup substitution injection")
def test_drh1_atomic_restore_cleanup_preserves_and_reports_a_replacement_subtree(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    (source / "a-nested").mkdir(parents=True)
    (source / "a-nested" / "state.json").write_bytes(b"nested")
    (source / "z-later.json").write_bytes(b"later")
    archive = tmp_path / "snapshot.shisad-backup"
    create_data_backup(source, archive)
    destination = tmp_path / "restored"
    displaced = tmp_path / "displaced-nested"

    monkeypatch.setattr(
        data_root_handle_module._PosixRootHandle,
        "supports_atomic_cleanup",
        property(lambda _root: True),
    )

    def replace_then_fail(relative: PurePosixPath) -> None:
        if relative == PurePosixPath("z-later.json"):
            (destination / "a-nested").rename(displaced)
            (destination / "a-nested").mkdir()
            (destination / "a-nested" / "replacement.txt").write_bytes(b"replacement")
            raise OSError("injected later sibling failure")

    with pytest.raises(DataBackupError, match=r"partial destination retained"):
        restore_data_backup(archive, destination, fault_injector=replace_then_fail)

    assert (destination / "a-nested" / "replacement.txt").read_bytes() == b"replacement"
    assert (displaced / "state.json").read_bytes() == b"nested"


def test_drh1_restore_permission_failure_retains_posix_residue(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    _representative_root(source)
    archive = tmp_path / "snapshot.shisad-backup"
    create_data_backup(source, archive)
    destination = tmp_path / "restored"
    original_chmod = data_root_handle_module._PosixRootHandle.chmod
    failed = False

    def fail_child_permission(
        root: data_root_handle_module._PosixRootHandle,
        relative: PurePosixPath,
        mode: int,
        *,
        expected_identity: tuple[int, int] | None = None,
    ) -> str:
        nonlocal failed
        if root.path != destination and relative == PurePosixPath(".") and not failed:
            failed = True
            return "failed"
        return original_chmod(root, relative, mode, expected_identity=expected_identity)

    monkeypatch.setattr(data_root_handle_module._PosixRootHandle, "chmod", fail_child_permission)

    with pytest.raises(DataBackupError, match=r"permission|restore|retained"):
        restore_data_backup(archive, destination)

    assert failed
    assert destination.exists()
    assert _payload_paths(destination)


def test_o4c_backup_refuses_if_published_inode_was_not_verified(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    _representative_root(source)
    archive = tmp_path / "snapshot.shisad-backup"
    original_publish = data_root_handle_module._PosixRootHandle.publish

    def replace_before_publish(
        root: data_root_handle_module._PosixRootHandle,
        temporary: PurePosixPath,
        destination: PurePosixPath,
        *,
        expected_identity: tuple[int, int],
        verified_descriptor: int,
    ) -> None:
        root.unlink(temporary, expected_identity=expected_identity)
        descriptor = root.create_file(temporary, 0o600)
        with os.fdopen(descriptor, "wb") as replacement:
            replacement.write(b"unverified replacement")
        original_publish(
            root,
            temporary,
            destination,
            expected_identity=expected_identity,
            verified_descriptor=verified_descriptor,
        )

    monkeypatch.setattr(data_root_handle_module._PosixRootHandle, "publish", replace_before_publish)

    with pytest.raises(DataBackupError, match=r"publish|verified|changed"):
        create_data_backup(source, archive)

    assert archive.read_bytes() == b"unverified replacement"
