"""Stopped-daemon, manifest-verified data-root backup and restore."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import uuid
import zipfile
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import IO, cast

from filelock import Timeout

from shisad.core.data_root_handle import (
    EntryMetadata,
    Identity,
    RootHandle,
    RootHandleError,
    RootHandleNotFound,
    open_root,
)
from shisad.core.data_root_lock import RootedFileLock
from shisad.core.storage_platform import (
    combine_permission_capabilities,
    hardened_open_flags,
)

_FORMAT_VERSION = 1
_MANIFEST_NAME = "manifest.json"
_PAYLOAD_PREFIX = "data/"
_LOCK_NAME = ".shisad.lock"
_MAX_MANIFEST_BYTES = 16 * 1024 * 1024
_COPY_CHUNK_BYTES = 1024 * 1024
_MANIFEST_FIELDS = frozenset(
    "backup_id created_at entries excluded format_version source_root_fingerprint".split()  # noqa: SIM905
)


class DataBackupError(RuntimeError):
    """A data-root backup or restore was refused or failed safely."""


def _ensure(condition: bool, message: str) -> None:
    if not condition:
        raise DataBackupError(message)


def _close_descriptor(descriptor: int) -> None:
    if descriptor >= 0:
        with suppress(OSError):
            os.close(descriptor)


@dataclass(frozen=True, slots=True)
class _DataTransferResult:
    backup_id: str
    destination: Path
    source_root_fingerprint: str
    file_count: int
    directory_count: int
    total_bytes: int
    verified: bool
    permissions: str
    parent_sync: str


@dataclass(frozen=True, slots=True)
class DataBackupResult(_DataTransferResult):
    source: Path


@dataclass(frozen=True, slots=True)
class DataRestoreResult(_DataTransferResult):
    archive: Path


@dataclass(frozen=True, slots=True)
class _Entry:
    path: PurePosixPath
    kind: str
    mode: int
    size: int
    sha256: str | None


@dataclass(frozen=True, slots=True)
class _Manifest:
    backup_id: str
    created_at: str
    source_root_fingerprint: str
    entries: tuple[_Entry, ...]

    def select(self, kind: str) -> tuple[_Entry, ...]:
        return tuple(entry for entry in self.entries if entry.kind == kind)

    def as_payload(self) -> dict[str, object]:
        return asdict(self) | {
            "entries": [asdict(entry) | {"path": entry.path.as_posix()} for entry in self.entries],
            "excluded": [".shisad.lock", "paths_outside_data_root"],
            "format_version": _FORMAT_VERSION,
        }


def create_data_backup(source: Path, destination: Path) -> DataBackupResult:
    source_path = Path(source)
    destination_path = Path(destination)
    resolved_source, source_fingerprint = _validate_backup_source(source_path)
    temporary = PurePosixPath(f".{destination_path.name}.{uuid.uuid4().hex}.tmp")
    destination_name = PurePosixPath(destination_path.name)
    temporary_started = False
    non_atomic_cleanup = False
    try:
        with (
            open_root(source_path) as source_root,
            open_root(destination_path.parent) as publication_root,
        ):
            non_atomic_cleanup = not publication_root.supports_atomic_cleanup
            publication_root.require_path_identity()
            try:
                resolved_parent = destination_path.parent.resolve(strict=True)
            except OSError as exc:
                raise DataBackupError("backup destination parent could not be inspected") from exc
            publication_root.require_path_identity()
            if (resolved_parent / destination_name.name).is_relative_to(resolved_source):
                raise DataBackupError("backup destination cannot be inside the data root")
            try:
                publication_root.metadata(destination_name)
            except RootHandleNotFound:
                pass
            except RootHandleError as exc:
                raise DataBackupError("backup destination is unsafe") from exc
            else:
                raise DataBackupError("backup destination exists; refusing to overwrite")
            lock = RootedFileLock(source_path, root=source_root, timeout=0)
            try:
                source_root.require_path_identity()
                lock.acquire(timeout=0)
            except Timeout:
                raise DataBackupError("data root is locked; stop shisad before backup") from None
            except OSError as exc:
                raise DataBackupError("data-root lock could not be acquired for backup") from exc
            try:
                source_root.require_path_identity()
                lock_metadata = source_root.metadata(PurePosixPath(_LOCK_NAME))
                _ensure(not lock_metadata.is_directory, "data-root lock path is unsafe")
                source_root.require_path_identity()
                temporary_started = True
                manifest, permissions, temporary_identity = _write_backup(
                    source_root,
                    publication_root,
                    temporary,
                    source_fingerprint,
                )
                with _verified_archive(
                    destination_path.parent / temporary.name,
                    root=publication_root,
                    relative=temporary,
                ) as (_bundle, verified, verified_identity, verified_descriptor):
                    _ensure(verified == manifest, "completed backup manifest did not verify")
                    _ensure(
                        verified_identity == temporary_identity,
                        "completed backup identity changed",
                    )
                    source_root.require_path_identity()
                    try:
                        publication_root.publish(
                            temporary,
                            destination_name,
                            expected_identity=verified_identity,
                            verified_descriptor=verified_descriptor,
                        )
                    except FileExistsError:
                        raise DataBackupError(
                            "backup destination exists; refusing to overwrite"
                        ) from None
                temporary_started = False
                try:
                    parent_sync = publication_root.sync()
                except RootHandleError:
                    parent_sync = "failed"
                # fmt: off
                return DataBackupResult(
                    manifest.backup_id, destination_path, manifest.source_root_fingerprint,
                    len(manifest.select("file")), len(manifest.select("directory")),
                    sum(entry.size for entry in manifest.select("file")), True, permissions,
                    parent_sync, source_path,
                )
                # fmt: on
            finally:
                lock.release()
                if publication_root.supports_atomic_cleanup:
                    with suppress(OSError, RootHandleError):
                        publication_root.unlink(temporary)
    except DataBackupError as exc:
        if temporary_started and non_atomic_cleanup:
            raise DataBackupError(
                f"{exc}; temporary or published backup residue may be retained in "
                f"{destination_path.parent}"
            ) from exc
        raise
    except (OSError, RootHandleError) as exc:
        if temporary_started and non_atomic_cleanup:
            raise DataBackupError(
                "data backup failed safely; temporary or published backup residue may be "
                f"retained in {destination_path.parent}: {exc}"
            ) from exc
        raise DataBackupError(f"data backup failed safely: {exc}") from exc


def restore_data_backup(
    archive: Path,
    destination: Path,
    *,
    fault_injector: Callable[[PurePosixPath], None] | None = None,
) -> DataRestoreResult:
    archive_path = Path(archive)
    destination_path = Path(destination)
    destination_name = PurePosixPath(destination_path.name)
    with _verified_archive(archive_path) as (
        bundle,
        manifest,
        _archive_identity,
        _verified_descriptor,
    ):
        try:
            publication_root = open_root(destination_path.parent)
        except RootHandleError as exc:
            raise DataBackupError("restore destination parent is unsafe or unavailable") from exc
        with publication_root:
            created_root = False
            root: RootHandle | None = None
            lock: RootedFileLock | None = None
            succeeded = False
            try:
                publication_root.require_path_identity()
                created_root, root = _prepare_restore_root(publication_root, destination_name)
                root_identity = root.identity
                lock = RootedFileLock(destination_path, root=root, timeout=0)
                try:
                    lock.acquire(timeout=0)
                except Timeout:
                    raise DataBackupError(
                        "restore root is locked; stop shisad before restore"
                    ) from None
                except OSError as exc:
                    raise DataBackupError(
                        "data-root lock could not be acquired for restore"
                    ) from exc
                lock_metadata = root.metadata(PurePosixPath(_LOCK_NAME))
                _ensure(not lock_metadata.is_directory, "restore lock path is unsafe")
                root_listing = root.listdir()
                if any(name != _LOCK_NAME for name in root_listing):
                    raise DataBackupError("restore destination must be empty")
                permissions = _restore_verified_entries(
                    bundle,
                    manifest,
                    root,
                    fault_injector=fault_injector,
                )
                root.require_path_identity()
                publication_root.require_path_identity()
                try:
                    parent_sync = root.sync()
                except RootHandleError:
                    parent_sync = "failed"
                # fmt: off
                result = DataRestoreResult(
                    manifest.backup_id, destination_path, manifest.source_root_fingerprint,
                    len(manifest.select("file")), len(manifest.select("directory")),
                    sum(entry.size for entry in manifest.select("file")), True, permissions,
                    parent_sync, archive_path,
                )
                # fmt: on
                succeeded = True
                return result
            except Exception as exc:
                residue = (
                    f"; partial destination retained at {destination_path}"
                    if root is not None and not root.supports_atomic_cleanup
                    else ""
                )
                raise DataBackupError(f"data restore failed safely{residue}: {exc}") from exc
            finally:
                if lock is not None:
                    lock_identity = lock.identity
                    lock.release()
                else:
                    lock_identity = None
                if root is not None:
                    if (
                        not succeeded
                        and created_root
                        and root.supports_atomic_cleanup
                        and lock_identity is not None
                    ):
                        with suppress(OSError, RootHandleError):
                            root.unlink(
                                PurePosixPath(_LOCK_NAME),
                                expected_identity=lock_identity,
                            )
                    root.close()
                if (
                    not succeeded
                    and created_root
                    and root is not None
                    and root.supports_atomic_cleanup
                ):
                    with suppress(OSError, RootHandleError):
                        publication_root.rmdir(destination_name, expected_identity=root_identity)


def _validate_backup_source(source: Path) -> tuple[Path, str]:
    try:
        source_metadata = source.stat(follow_symlinks=False)
        resolved_source = source.resolve(strict=True)
    except OSError as exc:
        raise DataBackupError("backup source could not be inspected") from exc
    if not stat.S_ISDIR(source_metadata.st_mode):
        raise DataBackupError("backup source must be an existing non-symlink data root")
    fingerprint = hashlib.sha256(str(resolved_source).encode()).hexdigest()
    return resolved_source, fingerprint


def _prepare_restore_root(
    publication_root: RootHandle,
    destination: PurePosixPath,
) -> tuple[bool, RootHandle]:
    try:
        root = publication_root.open_child_directory(destination)
        created = False
    except RootHandleNotFound:
        try:
            identity = publication_root.create_directory(destination, 0o700)
            root = publication_root.open_child_directory(destination, expected_identity=identity)
        except FileExistsError:
            raise DataBackupError(
                "restore destination changed while it was being prepared"
            ) from None
        except RootHandleError as exc:
            raise DataBackupError("restore destination could not be created safely") from exc
        created = True
    except (FileExistsError, RootHandleError) as exc:
        raise DataBackupError(
            "restore destination must be an absent or empty ordinary directory"
        ) from exc
    if any(name != _LOCK_NAME for name in root.listdir()):
        root.close()
        raise DataBackupError("restore destination must be empty")
    return created, root


def _write_backup(
    source: RootHandle,
    publication_root: RootHandle,
    temporary: PurePosixPath,
    source_fingerprint: str,
) -> tuple[_Manifest, str, Identity]:
    descriptor = -1
    entries: list[_Entry] = []
    temporary_identity: Identity | None = None
    try:
        descriptor = publication_root.create_file(temporary, 0o600)
        with os.fdopen(descriptor, "w+b") as archive_file:
            descriptor = -1
            with zipfile.ZipFile(
                archive_file,
                "w",
                compression=zipfile.ZIP_STORED,
                allowZip64=True,
            ) as bundle:
                _write_source_tree(bundle, source, PurePosixPath("."), entries)
                manifest = _Manifest(
                    str(uuid.uuid4()),
                    datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                    source_fingerprint,
                    tuple(sorted(entries, key=lambda entry: entry.path.as_posix())),
                )
                with bundle.open(_zip_info(_MANIFEST_NAME, 0o600), "w") as target:
                    target.write(_canonical_manifest(manifest))
            archive_file.flush()
            os.fsync(archive_file.fileno())
            temporary_identity = publication_root.descriptor_identity(archive_file.fileno())
        _ensure(temporary_identity is not None, "backup temporary identity is unavailable")
        permissions = publication_root.chmod(temporary, 0o600, expected_identity=temporary_identity)
        _ensure(permissions != "failed", "backup archive permissions could not be tightened")
        return manifest, permissions, temporary_identity
    except (OSError, RootHandleError, zipfile.BadZipFile) as exc:
        raise DataBackupError(f"backup creation failed safely: {exc}") from exc
    finally:
        _close_descriptor(descriptor)


def _write_source_file(
    bundle: zipfile.ZipFile,
    source: RootHandle,
    name: PurePosixPath,
    archive_path: PurePosixPath,
    metadata: EntryMetadata,
) -> _Entry:
    descriptor = source.open_file(
        name,
        os.O_RDONLY,
        expected_identity=metadata.identity,
    )
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or source.descriptor_identity(descriptor) != metadata.identity
            or stat.S_IMODE(before.st_mode) & 0o700 != metadata.mode
        ):
            raise DataBackupError(f"data-root entry changed during backup: {archive_path}")
        info = _zip_info(f"{_PAYLOAD_PREFIX}{archive_path.as_posix()}", metadata.mode)
        with os.fdopen(descriptor, "rb") as source_file, bundle.open(info, "w") as target:
            descriptor = -1
            size, digest = _copy_digest(source_file, target)
            after = os.fstat(source_file.fileno())
        if (
            size != after.st_size
            or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
            or before.st_mode != after.st_mode
        ):
            raise DataBackupError(f"data-root entry changed during backup: {archive_path}")
        current = source.metadata(name)
        if current.identity != metadata.identity or current.mode != metadata.mode:
            raise DataBackupError(f"data-root entry changed during backup: {archive_path}")
        return _Entry(archive_path, "file", metadata.mode, size, digest)
    finally:
        _close_descriptor(descriptor)


def _write_source_tree(
    bundle: zipfile.ZipFile,
    source: RootHandle,
    prefix: PurePosixPath,
    entries: list[_Entry],
) -> None:
    try:
        names = source.listdir()
    except RootHandleError as exc:
        raise DataBackupError(f"data-root scan failed at: {prefix}") from exc
    for raw_name in names:
        if prefix == PurePosixPath(".") and raw_name == _LOCK_NAME:
            continue
        name = PurePosixPath(raw_name)
        archive_path = name if prefix == PurePosixPath(".") else prefix / name
        try:
            metadata = source.metadata(name)
        except RootHandleError as exc:
            raise DataBackupError(f"data-root entry inspection failed: {archive_path}") from exc
        if metadata.is_directory:
            entries.append(_Entry(archive_path, "directory", metadata.mode, 0, None))
            with source.open_child_directory(name, expected_identity=metadata.identity) as child:
                _write_source_tree(bundle, child, archive_path, entries)
                child.require_path_identity()
            continue
        entries.append(_write_source_file(bundle, source, name, archive_path, metadata))


def _zip_info(name: str, mode: int) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_STORED
    info.external_attr = (stat.S_IFREG | mode) << 16
    return info


def _canonical_manifest(manifest: _Manifest) -> bytes:
    payload = json.dumps(manifest.as_payload(), sort_keys=True, separators=(",", ":"))
    return payload.encode("utf-8") + b"\n"


@contextmanager
def _open_archive(
    archive: Path,
    *,
    root: RootHandle | None = None,
    relative: PurePosixPath | None = None,
) -> Iterator[tuple[zipfile.ZipFile, Identity, int]]:
    archive_file: IO[bytes]
    try:
        if root is None:
            path_metadata = archive.stat(follow_symlinks=False)
            if not stat.S_ISREG(path_metadata.st_mode):
                raise DataBackupError("backup archive must be a non-symlink regular file")
            archive_file = open(  # noqa: SIM115
                archive,
                "rb",
                opener=lambda path, flags: os.open(path, hardened_open_flags(flags)),
            )
            expected_identity = (path_metadata.st_dev, path_metadata.st_ino)
        else:
            if relative is None:
                raise DataBackupError("rooted archive name is missing")
            expected_identity = root.metadata(relative).identity
            archive_file = cast(
                IO[bytes],
                os.fdopen(
                    root.open_file(
                        relative,
                        os.O_RDONLY,
                        expected_identity=expected_identity,
                        for_publication=True,
                    ),
                    "rb",
                ),
            )
    except (OSError, RootHandleError) as exc:
        raise DataBackupError("backup archive is invalid") from exc
    with archive_file:
        metadata = os.fstat(archive_file.fileno())
        identity = (
            root.descriptor_identity(archive_file.fileno())
            if root is not None
            else (metadata.st_dev, metadata.st_ino)
        )
        if not stat.S_ISREG(metadata.st_mode) or identity != expected_identity:
            raise DataBackupError("backup archive must be a non-symlink regular file")
        try:
            bundle = zipfile.ZipFile(archive_file, "r", allowZip64=True)
        except (OSError, zipfile.BadZipFile) as exc:
            raise DataBackupError("backup archive is invalid") from exc
        with bundle:
            yield bundle, identity, archive_file.fileno()


@contextmanager
def _verified_archive(
    archive: Path,
    *,
    root: RootHandle | None = None,
    relative: PurePosixPath | None = None,
) -> Iterator[tuple[zipfile.ZipFile, _Manifest, tuple[int, int], int]]:
    with _open_archive(archive, root=root, relative=relative) as (
        bundle,
        identity,
        descriptor,
    ):
        try:
            infos = bundle.infolist()
            names = [info.filename for info in infos]
            _ensure(len(names) == len(set(names)), "backup contains duplicate archive members")
            _ensure(_MANIFEST_NAME in names, "backup manifest is missing")
            for info in infos:
                name = info.filename
                if name != _MANIFEST_NAME:
                    if "\\" in name or not name.startswith(_PAYLOAD_PREFIX):
                        raise DataBackupError("backup member path is invalid")
                    _validate_relative_path(name.removeprefix(_PAYLOAD_PREFIX))
                if (
                    info.is_dir()
                    or info.compress_type != zipfile.ZIP_STORED
                    or info.flag_bits & 0x1
                    or not stat.S_ISREG(info.external_attr >> 16)
                ):
                    raise DataBackupError("backup contains a compressed or invalid member")
            manifest_info = bundle.getinfo(_MANIFEST_NAME)
            _ensure(manifest_info.file_size <= _MAX_MANIFEST_BYTES, "backup manifest is too large")
            manifest_bytes = bundle.read(manifest_info)
            manifest = _parse_manifest(manifest_bytes)
            if manifest_bytes != _canonical_manifest(manifest):
                raise DataBackupError("backup manifest is not canonical")
            expected_names = {_MANIFEST_NAME} | {
                f"{_PAYLOAD_PREFIX}{entry.path.as_posix()}" for entry in manifest.select("file")
            }
            _ensure(set(names) == expected_names, "backup contains an unexpected or missing member")
            for entry in manifest.select("file"):
                info = bundle.getinfo(f"{_PAYLOAD_PREFIX}{entry.path.as_posix()}")
                with bundle.open(info, "r") as source:
                    digest = _copy_digest(source)[1]
                if info.file_size != entry.size or digest != entry.sha256:
                    raise DataBackupError("backup payload size or digest does not match manifest")
        except (OSError, json.JSONDecodeError, UnicodeDecodeError, zipfile.BadZipFile) as exc:
            raise DataBackupError("backup archive or manifest is invalid") from exc
        yield bundle, manifest, identity, descriptor


def _validate_relative_path(value: str) -> PurePosixPath:
    path = PurePosixPath(value)
    if (
        not value
        or "\\" in value
        or path.is_absolute()
        or bool(PureWindowsPath(value).drive)
        or path.as_posix() != value
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise DataBackupError("backup member path is invalid")
    return path


def _parse_manifest(payload: bytes) -> _Manifest:
    raw = json.loads(payload.decode("utf-8"))
    _ensure(isinstance(raw, dict) and set(raw) == _MANIFEST_FIELDS, "invalid manifest structure")
    if type(raw["format_version"]) is not int or raw["format_version"] != _FORMAT_VERSION:
        raise DataBackupError("backup format version is unsupported")
    created_at = raw["created_at"]
    try:
        backup_id = str(uuid.UUID(str(raw["backup_id"])))
        if not isinstance(created_at, str) or "T" not in created_at or not created_at.endswith("Z"):
            raise ValueError
        datetime.fromisoformat(created_at.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise DataBackupError("backup identity or timestamp is invalid") from exc
    fingerprint = raw["source_root_fingerprint"]
    if (
        not isinstance(fingerprint, str)
        or len(fingerprint) != 64
        or any(char not in "0123456789abcdef" for char in fingerprint)
    ):
        raise DataBackupError("backup source-root fingerprint is invalid")
    if raw["excluded"] != [".shisad.lock", "paths_outside_data_root"]:
        raise DataBackupError("backup exclusion declaration is invalid")
    _ensure(isinstance(raw["entries"], list), "backup entries must be a list")
    entries = tuple(_parse_entry(item) for item in raw["entries"])
    paths = [entry.path.as_posix() for entry in entries]
    _ensure(paths == sorted(paths) and len(paths) == len(set(paths)), "invalid manifest paths")
    kinds = {entry.path.as_posix(): entry.kind for entry in entries}
    for entry in entries:
        for parent in entry.path.parents:
            if parent != PurePosixPath(".") and kinds.get(parent.as_posix()) != "directory":
                raise DataBackupError("backup manifest parent structure is invalid")
    return _Manifest(backup_id, created_at, fingerprint, entries)


def _parse_entry(raw: object) -> _Entry:
    if not isinstance(raw, dict) or set(raw) != {"kind", "mode", "path", "sha256", "size"}:
        raise DataBackupError("backup manifest entry is invalid")
    if not isinstance(raw["path"], str) or not isinstance(raw["kind"], str):
        raise DataBackupError("backup manifest entry metadata is invalid")
    path = _validate_relative_path(raw["path"])
    _ensure(path != PurePosixPath(_LOCK_NAME), "backup manifest contains a reserved lock entry")
    kind, mode, size, digest = (raw[key] for key in ("kind", "mode", "size", "sha256"))
    if kind not in {"directory", "file"} or type(mode) is not int or not 0 <= mode <= 0o700:
        raise DataBackupError("backup manifest entry metadata is invalid")
    _ensure(type(size) is int and size >= 0, "backup manifest entry size is invalid")
    if kind == "directory":
        if size != 0 or digest is not None:
            raise DataBackupError("backup directory entry is invalid")
    elif (
        not isinstance(digest, str)
        or len(digest) != 64
        or any(char not in "0123456789abcdef" for char in digest)
    ):
        raise DataBackupError("backup file digest is invalid")
    return _Entry(path, kind, mode, size, digest)


def _copy_digest(source: IO[bytes], target: IO[bytes] | None = None) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    while chunk := source.read(_COPY_CHUNK_BYTES):
        if target is not None:
            target.write(chunk)
        digest.update(chunk)
        size += len(chunk)
    return size, digest.hexdigest()


def _restore_verified_entries(
    bundle: zipfile.ZipFile,
    manifest: _Manifest,
    root: RootHandle,
    *,
    fault_injector: Callable[[PurePosixPath], None] | None,
) -> str:
    root_permission = root.chmod(PurePosixPath("."), 0o700, expected_identity=root.identity)
    permission_states = [root_permission]
    _ensure(permission_states[-1] != "failed", "restored root permissions failed")
    children: dict[PurePosixPath, list[_Entry]] = {}
    for entry in manifest.entries:
        parent = (
            PurePosixPath(".")
            if len(entry.path.parts) == 1
            else PurePosixPath(*entry.path.parts[:-1])
        )
        children.setdefault(parent, []).append(entry)
    _restore_directory_entries(
        bundle,
        root,
        PurePosixPath("."),
        children,
        permission_states,
        fault_injector,
    )
    return combine_permission_capabilities(*permission_states)


def _restore_directory_entries(
    bundle: zipfile.ZipFile,
    root: RootHandle,
    prefix: PurePosixPath,
    children: dict[PurePosixPath, list[_Entry]],
    permission_states: list[str],
    fault_injector: Callable[[PurePosixPath], None] | None,
) -> None:
    created_files: list[tuple[PurePosixPath, Identity]] = []
    created_directories: list[tuple[PurePosixPath, Identity]] = []
    try:
        for entry in children.get(prefix, []):
            name = PurePosixPath(entry.path.name)
            if entry.kind == "directory":
                try:
                    identity = root.create_directory(name, 0o700)
                except FileExistsError:
                    raise DataBackupError(f"restore target already exists: {entry.path}") from None
                except RootHandleError as exc:
                    raise DataBackupError(
                        f"restore directory could not be created safely: {entry.path}"
                    ) from exc
                created_directories.append((name, identity))
                with root.open_child_directory(name, expected_identity=identity) as child:
                    _restore_directory_entries(
                        bundle,
                        child,
                        entry.path,
                        children,
                        permission_states,
                        fault_injector,
                    )
                    permission = child.chmod(
                        PurePosixPath("."), entry.mode, expected_identity=identity
                    )
                    _ensure(permission != "failed", "restored owner permissions failed")
                    permission_states.append(permission)
                    child.require_path_identity()
                continue
            descriptor = -1
            try:
                descriptor = root.create_file(name, 0o600)
                identity = root.descriptor_identity(descriptor)
                created_files.append((name, identity))
                with (
                    bundle.open(f"{_PAYLOAD_PREFIX}{entry.path.as_posix()}", "r") as source,
                    os.fdopen(descriptor, "wb", closefd=False) as target,
                ):
                    size, digest = _copy_digest(source, target)
                    target.flush()
                if size != entry.size or digest != entry.sha256:
                    raise DataBackupError(f"restored payload verification failed: {entry.path}")
                permission = root.chmod(name, entry.mode, expected_identity=identity)
                _ensure(permission != "failed", "restored owner permissions failed")
                permission_states.append(permission)
                os.fsync(descriptor)
            finally:
                _close_descriptor(descriptor)
            if fault_injector is not None:
                fault_injector(entry.path)
    except Exception:
        if root.supports_atomic_cleanup:
            for name, identity in reversed(created_files):
                with suppress(OSError, RootHandleError):
                    root.unlink(name, expected_identity=identity)
            for name, identity in reversed(created_directories):
                with suppress(OSError, RootHandleError):
                    root.rmdir(name, expected_identity=identity)
        raise
