"""DRH1 native Windows rooted-directory contracts."""

from __future__ import annotations

import ctypes
import os
from pathlib import Path, PurePosixPath

import pytest

import shisad.core.data_root_handle as data_root_handle_module
import shisad.core.data_root_windows as data_root_windows_module


class _FakeWindowsApi:
    def __init__(self) -> None:
        self.calls: list[tuple[object, ...]] = []
        self.metadata_by_handle = {
            1: data_root_handle_module.EntryMetadata((7, 1), 0o700, 0, 0, True),
            2: data_root_handle_module.EntryMetadata((7, 2), 0o700, 0, 0, True),
        }

    def listdir(self, handle: int) -> tuple[str, ...]:
        self.calls.append(("listdir", handle))
        return ("state.json", "nested")

    def metadata(self, handle: int) -> data_root_handle_module.EntryMetadata:
        return self.metadata_by_handle[handle]

    def open_relative(self, parent: int, name: str, **kwargs: object) -> int:
        self.calls.append(("open", parent, name, kwargs))
        return 2

    def from_fd(self, descriptor: int) -> int:
        self.calls.append(("from_fd", descriptor))
        return 2

    def close(self, handle: int) -> None:
        self.calls.append(("close", handle))


def test_drh1_windows_listdir_enumerates_the_opened_handle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = _FakeWindowsApi()
    root = data_root_windows_module._WindowsRootHandle(
        tmp_path,
        1,
        (7, 1),
        api,  # type: ignore[arg-type]
    )
    monkeypatch.setattr(os, "listdir", lambda _path: pytest.fail("pathname enumeration used"))

    assert root.listdir() == ("nested", "state.json")
    with root.open_child_directory(PurePosixPath("nested"), expected_identity=(7, 2)) as child:
        assert child.listdir() == ("nested", "state.json")

    assert ("listdir", 1) in api.calls
    assert ("listdir", 2) in api.calls


def test_drh1_windows_descriptor_conversion_failure_closes_native_handle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = object.__new__(data_root_windows_module._WindowsNativeApi)
    closed: list[int] = []
    monkeypatch.setattr(data_root_windows_module, "msvcrt", None)
    monkeypatch.setattr(api, "close", closed.append)

    with pytest.raises(data_root_handle_module.RootHandleError, match=r"descriptor|unavailable"):
        api.into_fd(17, os.O_RDONLY)

    assert closed == [17]


def test_drh1_windows_unexpected_descriptor_conversion_failure_closes_native_handle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class BrokenMsvcrt:
        @staticmethod
        def open_osfhandle(_handle: int, _flags: int) -> int:
            raise RuntimeError("injected conversion failure")

    api = object.__new__(data_root_windows_module._WindowsNativeApi)
    closed: list[int] = []
    monkeypatch.setattr(data_root_windows_module, "msvcrt", BrokenMsvcrt())
    monkeypatch.setattr(os, "O_BINARY", 0, raising=False)
    monkeypatch.setattr(api, "close", closed.append)

    with pytest.raises(data_root_handle_module.RootHandleError, match=r"descriptor|unavailable"):
        api.into_fd(19, os.O_RDONLY)

    assert closed == [19]


def test_drh1_windows_descriptor_identity_uses_native_handle_metadata(tmp_path: Path) -> None:
    api = _FakeWindowsApi()
    root = data_root_windows_module._WindowsRootHandle(
        tmp_path,
        1,
        (7, 1),
        api,  # type: ignore[arg-type]
    )

    assert root.descriptor_identity(23) == (7, 2)
    assert ("from_fd", 23) in api.calls


def test_drh1_windows_root_metadata_permissions_and_lifecycle(tmp_path: Path) -> None:
    api = _FakeWindowsApi()
    root = data_root_windows_module._WindowsRootHandle(
        tmp_path,
        1,
        (7, 1),
        api,  # type: ignore[arg-type]
    )

    assert root.metadata(PurePosixPath(".")).identity == (7, 1)
    root.require_path_identity()
    assert root.chmod(PurePosixPath("."), 0o700, expected_identity=(7, 1)) == "unsupported"
    assert root.sync() == "unsupported"
    root.close()
    root.close()

    assert [call for call in api.calls if call == ("close", 1)] == [("close", 1)]


def test_drh1_windows_failed_delete_closes_the_verified_handle_once(tmp_path: Path) -> None:
    api = _FakeWindowsApi()
    api.metadata_by_handle[2] = data_root_handle_module.EntryMetadata((7, 2), 0o600, 0, 0, False)

    def fail_delete(_handle: int) -> None:
        raise data_root_handle_module.RootHandleError("delete failed")

    api.delete = fail_delete  # type: ignore[attr-defined]
    root = data_root_windows_module._WindowsRootHandle(
        tmp_path,
        1,
        (7, 1),
        api,  # type: ignore[arg-type]
    )

    with pytest.raises(data_root_handle_module.RootHandleError, match="delete"):
        root.unlink(PurePosixPath("state.json"), expected_identity=(7, 2))

    assert [call for call in api.calls if call == ("close", 2)] == [("close", 2)]


def test_drh1_windows_missing_metadata_maps_to_rooted_not_found(tmp_path: Path) -> None:
    api = _FakeWindowsApi()

    def missing(*_args: object, **_kwargs: object) -> int:
        raise FileNotFoundError("missing")

    api.open_relative = missing  # type: ignore[method-assign]
    root = data_root_windows_module._WindowsRootHandle(
        tmp_path,
        1,
        (7, 1),
        api,  # type: ignore[arg-type]
    )

    with pytest.raises(data_root_handle_module.RootHandleNotFound):
        root.metadata(PurePosixPath("missing"))


def test_drh1_windows_root_metadata_failure_closes_the_opened_handle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    closed: list[int] = []

    class FailingApi:
        def open_root(self, _path: Path) -> int:
            return 17

        def metadata(self, _handle: int) -> object:
            raise data_root_handle_module.RootHandleError("metadata failed")

        def close(self, handle: int) -> None:
            closed.append(handle)

    monkeypatch.setattr(data_root_windows_module, "_WindowsNativeApi", FailingApi)

    with pytest.raises(data_root_handle_module.RootHandleError, match="metadata"):
        data_root_windows_module.open_windows_root(tmp_path, None)

    assert closed == [17]


def test_drh1_windows_directory_buffer_parses_native_entries() -> None:
    header_type = data_root_windows_module._FileIdBothDirectoryInfoHeader
    header_size = ctypes.sizeof(header_type)
    first_name = ".".encode("utf-16-le")
    second_name = "state.json".encode("utf-16-le")
    next_offset = header_size + len(first_name)
    first = header_type()
    first.next_entry_offset = next_offset
    first.file_name_length = len(first_name)
    second = header_type()
    second.file_name_length = len(second_name)
    raw = bytes(first) + first_name + bytes(second) + second_name

    assert data_root_windows_module._parse_directory_buffer(raw) == ("state.json",)


def test_drh1_windows_directory_buffer_rejects_malformed_offsets() -> None:
    header_type = data_root_windows_module._FileIdBothDirectoryInfoHeader
    header = header_type()
    header.next_entry_offset = ctypes.sizeof(header_type) - 1

    with pytest.raises(data_root_handle_module.RootHandleError, match="malformed"):
        data_root_windows_module._parse_directory_buffer(bytes(header))
