"""Native Windows rooted-directory operations for data recovery."""

from __future__ import annotations

import ctypes
import os
from pathlib import Path, PurePosixPath
from typing import Any, ClassVar

from shisad.core.data_root_handle import (
    _ROOT,
    EntryMetadata,
    Identity,
    RootHandleError,
    RootHandleNotFound,
    _RootContext,
    _single_name,
)

try:
    import msvcrt
except ImportError:  # pragma: win32 cover
    msvcrt = None  # type: ignore[assignment]

_FILE_ATTRIBUTE_DIRECTORY = 0x00000010
_FILE_ATTRIBUTE_DEVICE = 0x00000040
_FILE_ATTRIBUTE_NORMAL = 0x00000080
_FILE_ATTRIBUTE_READONLY = 0x00000001
_FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
_FILE_LIST_DIRECTORY = 0x00000001
_FILE_READ_ATTRIBUTES = 0x00000080
_DELETE = 0x00010000
_SYNCHRONIZE = 0x00100000
_GENERIC_READ = 0x80000000
_GENERIC_WRITE = 0x40000000
_FILE_SHARE_READ = 0x00000001
_FILE_SHARE_WRITE = 0x00000002
_FILE_SHARE_DELETE = 0x00000004
_FILE_OPEN = 0x00000001
_FILE_CREATE = 0x00000002
_FILE_OPEN_IF = 0x00000003
_FILE_DIRECTORY_FILE = 0x00000001
_FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020
_FILE_NON_DIRECTORY_FILE = 0x00000040
_FILE_OPEN_REPARSE_POINT = 0x00200000
_OBJ_CASE_INSENSITIVE = 0x00000040
_OPEN_EXISTING = 3
_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
_FILE_ID_INFO_CLASS = 18
_FILE_ID_BOTH_DIRECTORY_INFO_CLASS = 0xA
_FILE_ID_BOTH_DIRECTORY_RESTART_INFO_CLASS = 0xB
_FILE_RENAME_INFORMATION_CLASS = 10
_FILE_DISPOSITION_INFO_CLASS = 4
_ERROR_NO_MORE_FILES = 18
_DIRECTORY_BUFFER_BYTES = 64 * 1024


class _FileTime(ctypes.Structure):
    _fields_ = [("low", ctypes.c_uint32), ("high", ctypes.c_uint32)]


class _ByHandleFileInformation(ctypes.Structure):
    _fields_ = [
        ("attributes", ctypes.c_uint32),
        ("creation_time", _FileTime),
        ("access_time", _FileTime),
        ("write_time", _FileTime),
        ("volume_serial", ctypes.c_uint32),
        ("size_high", ctypes.c_uint32),
        ("size_low", ctypes.c_uint32),
        ("link_count", ctypes.c_uint32),
        ("file_index_high", ctypes.c_uint32),
        ("file_index_low", ctypes.c_uint32),
    ]


class _FileId128(ctypes.Structure):
    _fields_ = [("identifier", ctypes.c_ubyte * 16)]


class _FileIdInfo(ctypes.Structure):
    _fields_ = [("volume_serial", ctypes.c_uint64), ("file_id", _FileId128)]


class _FileIdBothDirectoryInfoHeader(ctypes.Structure):
    _fields_ = [
        ("next_entry_offset", ctypes.c_uint32),
        ("file_index", ctypes.c_uint32),
        ("creation_time", ctypes.c_int64),
        ("last_access_time", ctypes.c_int64),
        ("last_write_time", ctypes.c_int64),
        ("change_time", ctypes.c_int64),
        ("end_of_file", ctypes.c_int64),
        ("allocation_size", ctypes.c_int64),
        ("file_attributes", ctypes.c_uint32),
        ("file_name_length", ctypes.c_uint32),
        ("ea_size", ctypes.c_uint32),
        ("short_name_length", ctypes.c_ubyte),
        ("short_name", ctypes.c_uint16 * 12),
        ("file_id", ctypes.c_int64),
    ]


class _UnicodeString(ctypes.Structure):
    _fields_ = [
        ("length", ctypes.c_uint16),
        ("maximum_length", ctypes.c_uint16),
        ("buffer", ctypes.c_wchar_p),
    ]


class _ObjectAttributes(ctypes.Structure):
    _fields_ = [
        ("length", ctypes.c_uint32),
        ("root_directory", ctypes.c_void_p),
        ("object_name", ctypes.POINTER(_UnicodeString)),
        ("attributes", ctypes.c_uint32),
        ("security_descriptor", ctypes.c_void_p),
        ("security_quality_of_service", ctypes.c_void_p),
    ]


class _IoStatusValue(ctypes.Union):
    _fields_: ClassVar[Any] = [("status", ctypes.c_long), ("pointer", ctypes.c_void_p)]


class _IoStatusBlock(ctypes.Structure):
    _anonymous_ = ("value",)
    _fields_ = [("value", _IoStatusValue), ("information", ctypes.c_size_t)]


class _FileDispositionInfo(ctypes.Structure):
    _fields_ = [("delete_file", ctypes.c_int32)]


class _WindowsNativeApi:
    """Documented Windows handle APIs plus rooted NT child open/rename."""

    def __init__(self) -> None:
        loader = getattr(ctypes, "WinDLL", None)
        if loader is None:
            raise RootHandleError("native Windows root-relative operations are unavailable")
        self._kernel32: Any = loader("kernel32", use_last_error=True)
        self._ntdll: Any = loader("ntdll", use_last_error=True)
        self._kernel32.CreateFileW.restype = ctypes.c_void_p
        self._kernel32.GetFileInformationByHandleEx.restype = ctypes.c_int
        self._ntdll.NtCreateFile.restype = ctypes.c_long
        self._ntdll.NtSetInformationFile.restype = ctypes.c_long
        self._ntdll.RtlNtStatusToDosError.restype = ctypes.c_uint32

    def open_root(self, path: Path) -> int:
        handle = self._kernel32.CreateFileW(
            ctypes.c_wchar_p(str(path)),
            _FILE_LIST_DIRECTORY | _FILE_READ_ATTRIBUTES | _SYNCHRONIZE,
            _FILE_SHARE_READ | _FILE_SHARE_WRITE,
            None,
            _OPEN_EXISTING,
            _FILE_FLAG_BACKUP_SEMANTICS | _FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
        invalid = ctypes.c_void_p(-1).value
        if handle in {None, invalid}:
            self._raise_last_error("root directory could not be opened")
        assert handle is not None
        return int(handle)

    def open_relative(
        self,
        parent: int,
        name: str,
        *,
        desired_access: int,
        disposition: int,
        directory: bool | None,
        share_delete: bool = False,
    ) -> int:
        buffer = ctypes.create_unicode_buffer(name)
        length = len(name.encode("utf-16-le"))
        unicode_name = _UnicodeString(length, length + 2, ctypes.cast(buffer, ctypes.c_wchar_p))
        attributes = _ObjectAttributes(
            ctypes.sizeof(_ObjectAttributes),
            ctypes.c_void_p(parent),
            ctypes.pointer(unicode_name),
            _OBJ_CASE_INSENSITIVE,
            None,
            None,
        )
        io_status = _IoStatusBlock()
        options = _FILE_SYNCHRONOUS_IO_NONALERT | _FILE_OPEN_REPARSE_POINT
        if directory is True:
            options |= _FILE_DIRECTORY_FILE
        elif directory is False:
            options |= _FILE_NON_DIRECTORY_FILE
        handle = ctypes.c_void_p()
        share = _FILE_SHARE_READ | _FILE_SHARE_WRITE
        if share_delete:
            share |= _FILE_SHARE_DELETE
        status = self._ntdll.NtCreateFile(
            ctypes.byref(handle),
            desired_access,
            ctypes.byref(attributes),
            ctypes.byref(io_status),
            None,
            _FILE_ATTRIBUTE_NORMAL,
            share,
            disposition,
            options,
            None,
            0,
        )
        if int(status) < 0:
            self._raise_nt_error(int(status), f"rooted entry could not be opened: {name}")
        if handle.value is None:
            raise RootHandleError("native Windows returned an invalid rooted handle")
        return int(handle.value)

    def metadata(self, handle: int) -> EntryMetadata:
        basic = _ByHandleFileInformation()
        if not self._kernel32.GetFileInformationByHandle(
            ctypes.c_void_p(handle), ctypes.byref(basic)
        ):
            self._raise_last_error("rooted handle metadata is unavailable")
        file_id = _FileIdInfo()
        if not self._kernel32.GetFileInformationByHandleEx(
            ctypes.c_void_p(handle),
            _FILE_ID_INFO_CLASS,
            ctypes.byref(file_id),
            ctypes.sizeof(file_id),
        ):
            self._raise_last_error("rooted handle identity is unavailable")
        attributes = int(basic.attributes)
        if attributes & (_FILE_ATTRIBUTE_REPARSE_POINT | _FILE_ATTRIBUTE_DEVICE):
            raise RootHandleError("rooted entry is a reparse point or special file")
        is_directory = bool(attributes & _FILE_ATTRIBUTE_DIRECTORY)
        mode = 0o700 if is_directory else 0o400 if attributes & _FILE_ATTRIBUTE_READONLY else 0o600
        size = (int(basic.size_high) << 32) | int(basic.size_low)
        write_ticks = (int(basic.write_time.high) << 32) | int(basic.write_time.low)
        identifier = int.from_bytes(bytes(file_id.file_id.identifier), "little")
        return EntryMetadata(
            (int(file_id.volume_serial), identifier), mode, size, write_ticks * 100, is_directory
        )

    def listdir(self, handle: int) -> tuple[str, ...]:
        names: list[str] = []
        information_class = _FILE_ID_BOTH_DIRECTORY_RESTART_INFO_CLASS
        while True:
            buffer = ctypes.create_string_buffer(_DIRECTORY_BUFFER_BYTES)
            if not self._kernel32.GetFileInformationByHandleEx(
                ctypes.c_void_p(handle), information_class, buffer, ctypes.sizeof(buffer)
            ):
                code = int(ctypes.get_last_error())  # type: ignore[attr-defined, unused-ignore]
                if code == _ERROR_NO_MORE_FILES:
                    break
                self._raise_last_error("rooted directory could not be enumerated")
            names.extend(_parse_directory_buffer(buffer.raw))
            information_class = _FILE_ID_BOTH_DIRECTORY_INFO_CLASS
        return tuple(names)

    def into_fd(self, handle: int, flags: int) -> int:
        try:
            if msvcrt is None:
                raise OSError("Windows descriptor conversion is unavailable")
            return int(
                msvcrt.open_osfhandle(  # type: ignore[attr-defined, unused-ignore]
                    handle,
                    flags | os.O_BINARY,  # type: ignore[attr-defined, unused-ignore]
                )
            )
        except Exception as exc:
            self.close(handle)
            raise RootHandleError("native Windows descriptor conversion is unavailable") from exc

    def from_fd(self, descriptor: int) -> int:
        if msvcrt is None:
            raise RootHandleError("native Windows descriptor lookup is unavailable")
        return int(msvcrt.get_osfhandle(descriptor))  # type: ignore[attr-defined, unused-ignore]

    def delete(self, handle: int) -> None:
        disposition = _FileDispositionInfo(1)
        if not self._kernel32.SetFileInformationByHandle(
            ctypes.c_void_p(handle),
            _FILE_DISPOSITION_INFO_CLASS,
            ctypes.byref(disposition),
            ctypes.sizeof(disposition),
        ):
            self._raise_last_error("rooted entry could not be removed")

    def rename(self, handle: int, root: int | None, destination: str) -> None:
        name_type = ctypes.c_wchar * (len(destination) + 2)

        class _FileRenameInfo(ctypes.Structure):
            _fields_ = [
                ("replace_if_exists", ctypes.c_ubyte),
                ("root_directory", ctypes.c_void_p),
                ("file_name_length", ctypes.c_uint32),
                ("file_name", name_type),
            ]

        info = _FileRenameInfo()
        info.replace_if_exists = 0
        info.root_directory = ctypes.c_void_p(root)
        info.file_name_length = len(destination.encode("utf-16-le"))
        info.file_name = destination
        io_status = _IoStatusBlock()
        status = self._ntdll.NtSetInformationFile(
            ctypes.c_void_p(handle),
            ctypes.byref(io_status),
            ctypes.byref(info),
            ctypes.sizeof(info),
            _FILE_RENAME_INFORMATION_CLASS,
        )
        if int(status) < 0:
            self._raise_nt_error(int(status), "verified artifact could not be published atomically")

    def close(self, handle: int) -> None:
        if handle:
            self._kernel32.CloseHandle(ctypes.c_void_p(handle))

    def _raise_nt_error(self, status: int, message: str) -> None:
        code = int(self._ntdll.RtlNtStatusToDosError(status))
        if code in {2, 3}:
            raise FileNotFoundError(code, message)
        if code in {80, 183}:
            raise FileExistsError(code, message)
        error = ctypes.WinError(code)  # type: ignore[attr-defined, unused-ignore]
        raise OSError(code, f"{message}: {error}")

    @staticmethod
    def _raise_last_error(message: str) -> None:
        code = int(ctypes.get_last_error())  # type: ignore[attr-defined, unused-ignore]
        error = ctypes.WinError(code)  # type: ignore[attr-defined, unused-ignore]
        raise OSError(code, f"{message}: {error}")


class _WindowsRootHandle(_RootContext):
    def __init__(
        self,
        path: Path,
        handle: int,
        identity: Identity,
        api: _WindowsNativeApi,
        *,
        anchor: _WindowsRootHandle | None = None,
        anchor_name: PurePosixPath | None = None,
    ) -> None:
        self.path = path
        self._handle = handle
        self.identity = identity
        self._api = api
        self._anchor = anchor
        self._anchor_name = anchor_name

    def close(self) -> None:
        if self._handle:
            handle, self._handle = self._handle, 0
            self._api.close(handle)

    @property
    def supports_atomic_cleanup(self) -> bool:
        return True

    def require_path_identity(self) -> None:
        if self._anchor is not None and self._anchor_name is not None:
            try:
                current = self._anchor.metadata(self._anchor_name)
            except RootHandleError as exc:
                raise RootHandleError("root directory identity changed or was replaced") from exc
            if current.identity != self.identity:
                raise RootHandleError("root directory identity changed or was replaced")
            return
        if self._api.metadata(self._handle).identity != self.identity:
            raise RootHandleError("root directory identity changed or was replaced")

    def listdir(self, relative: PurePosixPath = _ROOT) -> tuple[str, ...]:
        if relative != _ROOT:
            with self.open_child_directory(relative) as child:
                return child.listdir()
        names = self._api.listdir(self._handle)
        for name in names:
            _windows_name(PurePosixPath(name))
        return tuple(sorted(names))

    def open_child_directory(
        self,
        relative: PurePosixPath,
        *,
        expected_identity: Identity | None = None,
    ) -> _WindowsRootHandle:
        name = _windows_name(relative)
        try:
            handle = self._open(name, directory=True)
        except FileNotFoundError as exc:
            raise RootHandleNotFound(f"rooted directory does not exist: {relative}") from exc
        try:
            metadata = self._require_handle(handle, expected_identity, directory=True)
            return _WindowsRootHandle(
                self.path / name,
                handle,
                metadata.identity,
                self._api,
                anchor=self,
                anchor_name=PurePosixPath(name),
            )
        except Exception:
            self._api.close(handle)
            raise

    def metadata(self, relative: PurePosixPath) -> EntryMetadata:
        if relative == _ROOT:
            return self._api.metadata(self._handle)
        try:
            handle = self._open(_windows_name(relative), directory=None)
        except FileNotFoundError as exc:
            raise RootHandleNotFound(f"rooted entry does not exist: {relative}") from exc
        try:
            return self._api.metadata(handle)
        finally:
            self._api.close(handle)

    def open_file(
        self,
        relative: PurePosixPath,
        flags: int,
        *,
        expected_identity: Identity | None = None,
        for_publication: bool = False,
    ) -> int:
        access = _GENERIC_READ if flags & os.O_WRONLY == 0 else _GENERIC_WRITE
        if flags & os.O_RDWR:
            access = _GENERIC_READ | _GENERIC_WRITE
        access |= _SYNCHRONIZE
        if for_publication:
            access |= _DELETE
        handle = self._open(
            _windows_name(relative),
            desired_access=access,
            directory=False,
            share_delete=not for_publication,
        )
        try:
            self._require_handle(handle, expected_identity, directory=False)
        except Exception:
            self._api.close(handle)
            raise
        return self._api.into_fd(handle, flags)

    def open_directory(
        self,
        relative: PurePosixPath,
        *,
        expected_identity: Identity | None = None,
    ) -> int:
        handle = self._open(_windows_name(relative), directory=True)
        try:
            self._require_handle(handle, expected_identity, directory=True)
        except Exception:
            self._api.close(handle)
            raise
        return self._api.into_fd(handle, os.O_RDONLY)

    def descriptor_identity(self, descriptor: int) -> Identity:
        """Return Windows' stable file ID for an already-open descriptor."""

        return self._api.metadata(self._api.from_fd(descriptor)).identity

    def create_file(self, relative: PurePosixPath, mode: int) -> int:
        del mode
        handle = self._open(
            _windows_name(relative),
            desired_access=_GENERIC_READ | _GENERIC_WRITE | _SYNCHRONIZE,
            disposition=_FILE_CREATE,
            directory=False,
        )
        return self._api.into_fd(handle, os.O_RDWR)

    def ensure_file(self, relative: PurePosixPath, mode: int) -> int:
        del mode
        handle = self._open(
            _windows_name(relative),
            desired_access=_GENERIC_WRITE | _FILE_READ_ATTRIBUTES | _SYNCHRONIZE,
            disposition=_FILE_OPEN_IF,
            directory=False,
        )
        return self._api.into_fd(handle, os.O_WRONLY)

    def create_directory(self, relative: PurePosixPath, mode: int) -> Identity:
        del mode
        handle = self._open(
            _windows_name(relative),
            desired_access=_FILE_LIST_DIRECTORY | _FILE_READ_ATTRIBUTES | _SYNCHRONIZE,
            disposition=_FILE_CREATE,
            directory=True,
        )
        try:
            return self._require_handle(handle, None, directory=True).identity
        finally:
            self._api.close(handle)

    def chmod(
        self,
        relative: PurePosixPath,
        mode: int,
        *,
        expected_identity: Identity | None = None,
    ) -> str:
        del mode
        metadata = self.metadata(relative)
        if expected_identity is not None and metadata.identity != expected_identity:
            raise RootHandleError(f"rooted entry changed during operation: {relative}")
        return "unsupported"

    def unlink(self, relative: PurePosixPath, *, expected_identity: Identity | None = None) -> None:
        self._remove(relative, expected_identity, directory=False)

    def rmdir(self, relative: PurePosixPath, *, expected_identity: Identity | None = None) -> None:
        self._remove(relative, expected_identity, directory=True)

    def publish(
        self,
        temporary: PurePosixPath,
        destination: PurePosixPath,
        *,
        expected_identity: Identity,
        verified_descriptor: int,
    ) -> None:
        _windows_name(temporary)
        destination_name = _windows_name(destination)
        handle = self._api.from_fd(verified_descriptor)
        self._require_handle(handle, expected_identity, directory=False)
        self._api.rename(handle, self._handle, destination_name)
        self.require_path_identity()

    def sync(self) -> str:
        return "unsupported"

    def _remove(
        self,
        relative: PurePosixPath,
        expected_identity: Identity | None,
        *,
        directory: bool,
    ) -> None:
        handle = self._open(
            _windows_name(relative),
            desired_access=_DELETE | _FILE_READ_ATTRIBUTES | _SYNCHRONIZE,
            directory=directory,
            share_delete=True,
        )
        try:
            self._require_handle(handle, expected_identity, directory=directory)
            self._api.delete(handle)
        finally:
            self._api.close(handle)

    def _open(
        self,
        name: str,
        *,
        desired_access: int | None = None,
        disposition: int = _FILE_OPEN,
        directory: bool | None,
        share_delete: bool = False,
    ) -> int:
        access = desired_access
        if access is None:
            access = _FILE_LIST_DIRECTORY | _FILE_READ_ATTRIBUTES | _SYNCHRONIZE
        return self._api.open_relative(
            self._handle,
            name,
            desired_access=access,
            disposition=disposition,
            directory=directory,
            share_delete=share_delete,
        )

    def _require_handle(
        self,
        handle: int,
        expected_identity: Identity | None,
        *,
        directory: bool,
    ) -> EntryMetadata:
        metadata = self._api.metadata(handle)
        if metadata.is_directory != directory or (
            expected_identity is not None and metadata.identity != expected_identity
        ):
            raise RootHandleError("rooted entry identity or type changed")
        return metadata


def open_windows_root(path: Path, expected_identity: Identity | None) -> _WindowsRootHandle:
    api: _WindowsNativeApi | None = None
    handle = 0
    try:
        api = _WindowsNativeApi()
        handle = api.open_root(path)
        metadata = api.metadata(handle)
        if not metadata.is_directory or (
            expected_identity is not None and metadata.identity != expected_identity
        ):
            raise RootHandleError("root directory identity changed or was replaced")
        return _WindowsRootHandle(path, handle, metadata.identity, api)
    except RootHandleError:
        if api is not None and handle:
            api.close(handle)
        raise
    except OSError as exc:
        if api is not None and handle:
            api.close(handle)
        raise RootHandleError("native Windows root-relative open failed") from exc


def _parse_directory_buffer(raw: bytes) -> tuple[str, ...]:
    names: list[str] = []
    offset = 0
    header_size = ctypes.sizeof(_FileIdBothDirectoryInfoHeader)
    while True:
        if offset + header_size > len(raw):
            raise RootHandleError("native Windows directory enumeration was malformed")
        header = _FileIdBothDirectoryInfoHeader.from_buffer_copy(raw, offset)
        name_start = offset + header_size
        name_end = name_start + int(header.file_name_length)
        if name_end > len(raw) or int(header.file_name_length) % 2:
            raise RootHandleError("native Windows directory enumeration was malformed")
        try:
            name = raw[name_start:name_end].decode("utf-16-le")
        except UnicodeDecodeError as exc:
            raise RootHandleError("native Windows directory enumeration was malformed") from exc
        if name not in {".", ".."}:
            names.append(name)
        next_offset = int(header.next_entry_offset)
        if next_offset == 0:
            break
        record_end = offset + next_offset
        if next_offset < header_size or record_end >= len(raw) or name_end > record_end:
            raise RootHandleError("native Windows directory enumeration was malformed")
        offset = record_end
    return tuple(names)


def _windows_name(relative: PurePosixPath) -> str:
    name = _single_name(relative)
    if "\\" in name or ":" in name:
        raise RootHandleError("Windows rooted path contains an unsafe component")
    return name


__all__ = ["_WindowsNativeApi", "_WindowsRootHandle", "open_windows_root"]
