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

from filelock import FileLock, Timeout

from shisad.core.storage_platform import (
    combine_permission_capabilities,
    hardened_open_flags,
    sync_parent_directory,
    tighten_permissions,
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
class _SourceEntry:
    path: PurePosixPath
    kind: str
    mode: int
    device: int
    inode: int


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
    """Create and verify one owner-only backup without overwriting a target."""

    source_path = Path(source)
    destination_path = Path(destination)
    source_identity = _validate_backup_paths(source_path, destination_path)
    lock = FileLock(str(source_path / _LOCK_NAME), timeout=0)
    try:
        lock.acquire(timeout=0)
    except Timeout:
        raise DataBackupError("data root is locked; stop shisad before backup") from None
    except OSError as exc:
        raise DataBackupError("data-root lock could not be acquired for backup") from exc

    temporary = destination_path.with_name(f".{destination_path.name}.{uuid.uuid4().hex}.tmp")
    published = False
    try:
        _require_directory_identity(source_path, source_identity)
        source_entries = _scan_source(source_path)
        manifest, permissions = _write_backup(
            source_path,
            temporary,
            source_entries,
        )
        with _verified_archive(temporary) as (_bundle, verified):
            if verified != manifest:
                raise DataBackupError("completed backup manifest did not verify")
        _require_directory_identity(source_path, source_identity)
        try:
            os.link(temporary, destination_path)
        except FileExistsError:
            raise DataBackupError("backup destination exists; refusing to overwrite") from None
        except OSError as exc:
            raise DataBackupError("backup could not be published atomically") from exc
        published = True
        with suppress(OSError):
            temporary.unlink()
        try:
            parent_sync = sync_parent_directory(destination_path.parent)
        except OSError:
            parent_sync = "failed"
        return DataBackupResult(
            backup_id=manifest.backup_id,
            source=source_path,
            destination=destination_path,
            source_root_fingerprint=manifest.source_root_fingerprint,
            file_count=len(manifest.select("file")),
            directory_count=len(manifest.select("directory")),
            total_bytes=sum(entry.size for entry in manifest.select("file")),
            verified=True,
            permissions=permissions,
            parent_sync=parent_sync,
        )
    finally:
        lock.release()
        if not published:
            with suppress(OSError):
                temporary.unlink()


def restore_data_backup(
    archive: Path,
    destination: Path,
    *,
    fault_injector: Callable[[PurePosixPath], None] | None = None,
) -> DataRestoreResult:
    """Verify a complete backup, then restore it into an absent or empty root."""

    archive_path = Path(archive)
    destination_path = Path(destination)
    created_root, root_identity = _prepare_restore_root(destination_path)
    lock = FileLock(str(destination_path / _LOCK_NAME), timeout=0)
    acquired = False
    succeeded = False
    root_descriptor = -1
    created_files: list[PurePosixPath] = []
    created_directories: list[PurePosixPath] = []
    try:
        try:
            lock.acquire(timeout=0)
            acquired = True
        except Timeout:
            raise DataBackupError("restore root is locked; stop shisad before restore") from None
        except OSError as exc:
            raise DataBackupError("data-root lock could not be acquired for restore") from exc
        root_descriptor = _open_restore_root(destination_path, root_identity)
        if [name for name in os.listdir(root_descriptor) if name != _LOCK_NAME]:
            raise DataBackupError("restore destination must be empty")
        with _verified_archive(archive_path) as (bundle, manifest):
            permissions = _restore_verified_entries(
                bundle,
                manifest,
                root_descriptor,
                created_files=created_files,
                created_directories=created_directories,
                fault_injector=fault_injector,
            )
        _require_directory_identity(destination_path, root_identity)
        try:
            parent_sync = sync_parent_directory(destination_path)
        except OSError:
            parent_sync = "failed"
        result = DataRestoreResult(
            backup_id=manifest.backup_id,
            archive=archive_path,
            destination=destination_path,
            source_root_fingerprint=manifest.source_root_fingerprint,
            file_count=len(manifest.select("file")),
            directory_count=len(manifest.select("directory")),
            total_bytes=sum(entry.size for entry in manifest.select("file")),
            verified=True,
            permissions=permissions,
            parent_sync=parent_sync,
        )
        lock.release()
        acquired = False
        flags = hardened_open_flags(os.O_WRONLY | os.O_CREAT)
        artifact = os.open(_LOCK_NAME, flags, 0o600, dir_fd=root_descriptor)
        os.close(artifact)
        succeeded = True
        return result
    except Exception as exc:
        if root_descriptor >= 0:
            _cleanup_restore_payload(root_descriptor, created_files, created_directories)
        if isinstance(exc, DataBackupError):
            raise
        raise DataBackupError(f"data restore failed safely: {exc}") from exc
    finally:
        if acquired:
            lock.release()
        if not succeeded and root_descriptor >= 0 and created_root:
            with suppress(OSError):
                os.unlink(_LOCK_NAME, dir_fd=root_descriptor)
        if root_descriptor >= 0:
            _close_descriptor(root_descriptor)
        if not succeeded and created_root:
            with suppress(DataBackupError, OSError):
                _require_directory_identity(destination_path, root_identity)
                destination_path.rmdir()


def _validate_backup_paths(source: Path, destination: Path) -> tuple[int, int]:
    try:
        source_metadata = source.stat(follow_symlinks=False)
    except OSError as exc:
        raise DataBackupError("backup source could not be inspected") from exc
    if not stat.S_ISDIR(source_metadata.st_mode):
        raise DataBackupError("backup source must be an existing non-symlink data root")
    lock_path = source / _LOCK_NAME
    if lock_path.is_symlink() or (lock_path.exists() and not lock_path.is_file()):
        raise DataBackupError("data-root lock path is unsafe")
    if destination.exists() or destination.is_symlink():
        raise DataBackupError("backup destination exists; refusing to overwrite")
    parent = destination.parent
    if parent.is_symlink() or not parent.is_dir():
        raise DataBackupError("backup destination parent must be an existing safe directory")
    source_resolved = source.resolve(strict=True)
    destination_resolved = destination.resolve(strict=False)
    if destination_resolved.is_relative_to(source_resolved):
        raise DataBackupError("backup destination cannot be inside the data root")
    return source_metadata.st_dev, source_metadata.st_ino


def _require_directory_identity(path: Path, identity: tuple[int, int]) -> None:
    try:
        metadata = path.stat(follow_symlinks=False)
    except OSError as exc:
        raise DataBackupError("data-root directory identity changed") from exc
    if not stat.S_ISDIR(metadata.st_mode) or (metadata.st_dev, metadata.st_ino) != identity:
        raise DataBackupError("data-root directory identity changed")


def _prepare_restore_root(destination: Path) -> tuple[bool, tuple[int, int]]:
    if destination.is_symlink():
        raise DataBackupError("restore destination cannot be a symlink")
    created = False
    if destination.exists():
        if not destination.is_dir():
            raise DataBackupError("restore destination must be an absent or empty directory")
        if any(path.name != _LOCK_NAME for path in destination.iterdir()):
            raise DataBackupError("restore destination must be empty")
    else:
        if destination.parent.is_symlink() or not destination.parent.is_dir():
            raise DataBackupError("restore destination parent must be an existing safe directory")
        destination.mkdir(mode=0o700)
        created = True
    lock_path = destination / _LOCK_NAME
    if lock_path.is_symlink() or (lock_path.exists() and not lock_path.is_file()):
        if created:
            with suppress(OSError):
                destination.rmdir()
        raise DataBackupError("restore lock path is unsafe")
    metadata = destination.stat(follow_symlinks=False)
    return created, (metadata.st_dev, metadata.st_ino)


def _open_restore_root(destination: Path, identity: tuple[int, int]) -> int:
    flags = hardened_open_flags(os.O_RDONLY | int(getattr(os, "O_DIRECTORY", 0)))
    try:
        descriptor = os.open(destination, flags)
    except OSError as exc:
        raise DataBackupError("restore destination was replaced or became unsafe") from exc
    metadata = os.fstat(descriptor)
    if not stat.S_ISDIR(metadata.st_mode) or (metadata.st_dev, metadata.st_ino) != identity:
        os.close(descriptor)
        raise DataBackupError("restore destination was replaced or became unsafe")
    return descriptor


def _tighten_descriptor(descriptor: int, mode: int) -> str:
    if os.name != "posix" or not hasattr(os, "fchmod"):
        return "unsupported"
    try:
        os.fchmod(descriptor, mode)
    except (AttributeError, NotImplementedError):
        return "unsupported"
    except OSError:
        return "failed"
    return "supported"


def _scan_source(root: Path) -> tuple[_SourceEntry, ...]:
    entries: list[_SourceEntry] = []
    for current_text, directory_names, file_names in os.walk(
        root, followlinks=False, onerror=_raise_scan_error
    ):
        current = Path(current_text)
        directory_names.sort()
        file_names.sort()
        for name in directory_names:
            entries.append(_scan_source_entry(root, current / name, "directory"))
        for name in file_names:
            if current == root and name == _LOCK_NAME:
                continue
            entries.append(_scan_source_entry(root, current / name, "file"))
    return tuple(sorted(entries, key=lambda entry: entry.path.as_posix()))


def _scan_source_entry(root: Path, path: Path, kind: str) -> _SourceEntry:
    metadata = _source_metadata(path)
    expected_type = stat.S_ISDIR if kind == "directory" else stat.S_ISREG
    if not expected_type(metadata.st_mode):
        raise DataBackupError(f"unsafe data-root entry: {path.relative_to(root)}")
    return _SourceEntry(
        PurePosixPath(path.relative_to(root).as_posix()),
        kind,
        stat.S_IMODE(metadata.st_mode) & 0o700,
        metadata.st_dev,
        metadata.st_ino,
    )


def _raise_scan_error(exc: OSError) -> None:
    raise DataBackupError(f"data-root scan failed: {exc}") from exc


def _source_metadata(path: Path) -> os.stat_result:
    try:
        return path.lstat()
    except OSError as exc:
        raise DataBackupError(f"data-root entry inspection failed: {path.name}") from exc


def _write_backup(
    source: Path,
    temporary: Path,
    source_entries: tuple[_SourceEntry, ...],
) -> tuple[_Manifest, str]:
    flags = hardened_open_flags(os.O_RDWR | os.O_CREAT | os.O_EXCL)
    descriptor = -1
    entries: list[_Entry] = []
    try:
        descriptor = os.open(temporary, flags, 0o600)
        with os.fdopen(descriptor, "w+b") as archive_file:
            descriptor = -1
            with zipfile.ZipFile(
                archive_file,
                "w",
                compression=zipfile.ZIP_STORED,
                allowZip64=True,
            ) as bundle:
                for source_entry in source_entries:
                    if source_entry.kind == "directory":
                        _verify_source_directory(source, source_entry)
                        entries.append(
                            _Entry(
                                path=source_entry.path,
                                kind="directory",
                                mode=source_entry.mode,
                                size=0,
                                sha256=None,
                            )
                        )
                        continue
                    entries.append(_write_source_file(bundle, source, source_entry))
                manifest = _Manifest(
                    backup_id=str(uuid.uuid4()),
                    created_at=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                    source_root_fingerprint=hashlib.sha256(
                        str(source.resolve(strict=True)).encode("utf-8")
                    ).hexdigest(),
                    entries=tuple(entries),
                )
                _write_zip_bytes(bundle, _MANIFEST_NAME, _canonical_manifest(manifest), 0o600)
            archive_file.flush()
            os.fsync(archive_file.fileno())
        permissions = tighten_permissions(temporary, 0o600)
        if permissions == "failed":
            raise DataBackupError("backup archive permissions could not be tightened")
        return manifest, permissions
    except (OSError, zipfile.BadZipFile) as exc:
        raise DataBackupError(f"backup creation failed safely: {exc}") from exc
    finally:
        _close_descriptor(descriptor)


def _write_source_file(
    bundle: zipfile.ZipFile,
    source: Path,
    entry: _SourceEntry,
) -> _Entry:
    path = source / Path(entry.path.as_posix())
    descriptor = os.open(path, hardened_open_flags(os.O_RDONLY))
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_dev != entry.device
            or before.st_ino != entry.inode
            or stat.S_IMODE(before.st_mode) & 0o700 != entry.mode
        ):
            raise DataBackupError(f"data-root entry changed during backup: {entry.path}")
        digest = hashlib.sha256()
        size = 0
        info = _zip_info(f"{_PAYLOAD_PREFIX}{entry.path.as_posix()}", entry.mode)
        with os.fdopen(descriptor, "rb") as source_file, bundle.open(info, "w") as target:
            descriptor = -1
            while chunk := source_file.read(_COPY_CHUNK_BYTES):
                target.write(chunk)
                digest.update(chunk)
                size += len(chunk)
            after = os.fstat(source_file.fileno())
        if (
            size != after.st_size
            or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
            or before.st_mode != after.st_mode
        ):
            raise DataBackupError(f"data-root entry changed during backup: {entry.path}")
        return _Entry(
            path=entry.path,
            kind="file",
            mode=entry.mode,
            size=size,
            sha256=digest.hexdigest(),
        )
    finally:
        _close_descriptor(descriptor)


def _verify_source_directory(source: Path, entry: _SourceEntry) -> None:
    path = source / Path(entry.path.as_posix())
    metadata = _source_metadata(path)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_dev != entry.device
        or metadata.st_ino != entry.inode
        or stat.S_IMODE(metadata.st_mode) & 0o700 != entry.mode
    ):
        raise DataBackupError(f"data-root entry changed during backup: {entry.path}")


def _write_zip_bytes(bundle: zipfile.ZipFile, name: str, payload: bytes, mode: int) -> None:
    with bundle.open(_zip_info(name, mode), "w") as target:
        target.write(payload)


def _zip_info(name: str, mode: int) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_STORED
    info.external_attr = (stat.S_IFREG | mode) << 16
    return info


def _canonical_manifest(manifest: _Manifest) -> bytes:
    return (json.dumps(manifest.as_payload(), sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )


@contextmanager
def _open_archive(archive: Path) -> Iterator[zipfile.ZipFile]:
    try:
        archive_file = open(archive, "rb", opener=_hardened_opener)  # noqa: SIM115
    except OSError as exc:
        raise DataBackupError("backup archive is invalid") from exc
    with archive_file:
        if not stat.S_ISREG(os.fstat(archive_file.fileno()).st_mode):
            raise DataBackupError("backup archive must be a non-symlink regular file")
        try:
            bundle = zipfile.ZipFile(archive_file, "r", allowZip64=True)
        except (OSError, zipfile.BadZipFile) as exc:
            raise DataBackupError("backup archive is invalid") from exc
        with bundle:
            yield bundle


def _hardened_opener(path: str, flags: int) -> int:
    return os.open(path, hardened_open_flags(flags))


@contextmanager
def _verified_archive(archive: Path) -> Iterator[tuple[zipfile.ZipFile, _Manifest]]:
    with _open_archive(archive) as bundle:
        try:
            infos = bundle.infolist()
            names = [info.filename for info in infos]
            if len(names) != len(set(names)):
                raise DataBackupError("backup contains duplicate archive members")
            if _MANIFEST_NAME not in names:
                raise DataBackupError("backup manifest is missing")
            for info in infos:
                _validate_member_name(info.filename)
                if (
                    info.is_dir()
                    or info.compress_type != zipfile.ZIP_STORED
                    or info.flag_bits & 0x1
                    or not stat.S_ISREG(info.external_attr >> 16)
                ):
                    raise DataBackupError("backup contains a compressed or invalid member")
            manifest_info = bundle.getinfo(_MANIFEST_NAME)
            if manifest_info.file_size > _MAX_MANIFEST_BYTES:
                raise DataBackupError("backup manifest exceeds the supported bound")
            manifest_bytes = bundle.read(manifest_info)
            manifest = _parse_manifest(manifest_bytes)
            if manifest_bytes != _canonical_manifest(manifest):
                raise DataBackupError("backup manifest is not canonical")
            expected_names = {_MANIFEST_NAME} | {
                f"{_PAYLOAD_PREFIX}{entry.path.as_posix()}" for entry in manifest.select("file")
            }
            if set(names) != expected_names:
                raise DataBackupError("backup contains an unexpected or missing member")
            for entry in manifest.select("file"):
                info = bundle.getinfo(f"{_PAYLOAD_PREFIX}{entry.path.as_posix()}")
                if info.file_size != entry.size or _zip_digest(bundle, info) != entry.sha256:
                    raise DataBackupError("backup payload size or digest does not match manifest")
        except (OSError, json.JSONDecodeError, UnicodeDecodeError, zipfile.BadZipFile) as exc:
            raise DataBackupError("backup archive or manifest is invalid") from exc
        yield bundle, manifest


def _validate_member_name(name: str) -> None:
    if name == _MANIFEST_NAME:
        return
    if "\\" in name or not name.startswith(_PAYLOAD_PREFIX):
        raise DataBackupError("backup member path is invalid")
    _validate_relative_path(name.removeprefix(_PAYLOAD_PREFIX))


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
    if not isinstance(raw, dict) or set(raw) != _MANIFEST_FIELDS:
        raise DataBackupError("backup manifest structure is invalid")
    if type(raw["format_version"]) is not int or raw["format_version"] != _FORMAT_VERSION:
        raise DataBackupError("backup format version is unsupported")
    created_at = raw["created_at"]
    try:
        backup_id = str(uuid.UUID(str(raw["backup_id"])))
        if not isinstance(created_at, str) or not created_at.endswith("Z"):
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
    if not isinstance(raw["entries"], list):
        raise DataBackupError("backup entries must be a list")
    entries = tuple(_parse_entry(item) for item in raw["entries"])
    paths = [entry.path.as_posix() for entry in entries]
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        raise DataBackupError("backup manifest paths must be sorted and unique")
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
    if path == PurePosixPath(_LOCK_NAME):
        raise DataBackupError("backup manifest contains a reserved root lock entry")
    kind = raw["kind"]
    mode = raw["mode"]
    size = raw["size"]
    digest = raw["sha256"]
    if kind not in {"directory", "file"} or type(mode) is not int or not 0 <= mode <= 0o700:
        raise DataBackupError("backup manifest entry metadata is invalid")
    if type(size) is not int or size < 0:
        raise DataBackupError("backup manifest entry size is invalid")
    if kind == "directory":
        if size != 0 or digest is not None:
            raise DataBackupError("backup directory entry is invalid")
    elif (
        not isinstance(digest, str)
        or len(digest) != 64
        or any(char not in "0123456789abcdef" for char in digest)
    ):
        raise DataBackupError("backup file digest is invalid")
    return _Entry(path=path, kind=kind, mode=mode, size=size, sha256=digest)


def _zip_digest(bundle: zipfile.ZipFile, info: zipfile.ZipInfo) -> str:
    digest = hashlib.sha256()
    with bundle.open(info, "r") as source:
        while chunk := source.read(_COPY_CHUNK_BYTES):
            digest.update(chunk)
    return digest.hexdigest()


def _restore_verified_entries(
    bundle: zipfile.ZipFile,
    manifest: _Manifest,
    root_descriptor: int,
    *,
    created_files: list[PurePosixPath],
    created_directories: list[PurePosixPath],
    fault_injector: Callable[[PurePosixPath], None] | None,
) -> str:
    permission_states = [_tighten_descriptor(root_descriptor, 0o700)]
    if permission_states[-1] == "failed":
        raise DataBackupError("restored root permissions could not be applied")
    for entry in manifest.select("directory"):
        try:
            os.mkdir(entry.path.as_posix(), mode=0o700, dir_fd=root_descriptor)
        except FileExistsError:
            raise DataBackupError(f"restore target already exists: {entry.path}") from None
        created_directories.append(entry.path)
    file_flags = hardened_open_flags(os.O_WRONLY | os.O_CREAT | os.O_EXCL)
    for entry in manifest.select("file"):
        descriptor = -1
        digest = hashlib.sha256()
        size = 0
        try:
            descriptor = os.open(entry.path.as_posix(), file_flags, 0o600, dir_fd=root_descriptor)
            created_files.append(entry.path)
            info = bundle.getinfo(f"{_PAYLOAD_PREFIX}{entry.path.as_posix()}")
            with (
                bundle.open(info, "r") as source,
                os.fdopen(descriptor, "wb", closefd=False) as target,
            ):
                while chunk := source.read(_COPY_CHUNK_BYTES):
                    target.write(chunk)
                    digest.update(chunk)
                    size += len(chunk)
                target.flush()
            if size != entry.size or digest.hexdigest() != entry.sha256:
                raise DataBackupError(f"restored payload verification failed: {entry.path}")
            permission = _tighten_descriptor(descriptor, entry.mode)
            if permission == "failed":
                raise DataBackupError("restored owner permissions could not be applied")
            permission_states.append(permission)
            os.fsync(descriptor)
        finally:
            _close_descriptor(descriptor)
        if fault_injector is not None:
            fault_injector(entry.path)
    directory_flags = hardened_open_flags(os.O_RDONLY | int(getattr(os, "O_DIRECTORY", 0)))
    for entry in sorted(
        manifest.select("directory"), key=lambda item: len(item.path.parts), reverse=True
    ):
        descriptor = os.open(entry.path.as_posix(), directory_flags, dir_fd=root_descriptor)
        try:
            permission = _tighten_descriptor(descriptor, entry.mode)
        finally:
            os.close(descriptor)
        if permission == "failed":
            raise DataBackupError("restored owner permissions could not be applied")
        permission_states.append(permission)
    return combine_permission_capabilities(*permission_states)


def _cleanup_restore_payload(
    root_descriptor: int,
    files: list[PurePosixPath],
    directories: list[PurePosixPath],
) -> None:
    for path in sorted(directories, key=lambda item: len(item.parts)):
        with suppress(OSError, ValueError, NotImplementedError):
            os.chmod(path.as_posix(), 0o700, dir_fd=root_descriptor, follow_symlinks=False)
    for path in reversed(files):
        with suppress(OSError):
            os.unlink(path.as_posix(), dir_fd=root_descriptor)
    for path in sorted(directories, key=lambda item: len(item.parts), reverse=True):
        with suppress(OSError):
            os.rmdir(path.as_posix(), dir_fd=root_descriptor)
    files.clear()
    directories.clear()
