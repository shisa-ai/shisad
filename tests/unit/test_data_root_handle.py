"""O4C-P rooted filesystem capability contracts."""

from __future__ import annotations

import ctypes
import os
from pathlib import Path, PurePosixPath

import pytest

import shisad.core.data_root_handle as data_root_handle_module
import shisad.core.data_root_windows as data_root_windows_module
from shisad.core.data_root_handle import RootHandleError, open_root

_POSIX_ONLY = pytest.mark.skipif(os.name != "posix", reason="POSIX backend contract")
_WINDOWS_ONLY = pytest.mark.skipif(os.name != "nt", reason="Windows backend contract")


class _FakeWindowsApi:
    def __init__(self) -> None:
        self.calls: list[tuple[object, ...]] = []
        self.metadata_by_handle = {
            1: data_root_handle_module.EntryMetadata((7, 1), 0o700, 0, 0, True),
            2: data_root_handle_module.EntryMetadata((7, 2), 0o700, 0, 0, True),
            3: data_root_handle_module.EntryMetadata((7, 3), 0o600, 8, 0, False),
        }

    def open_relative(self, parent: int, name: str, **kwargs: object) -> int:
        self.calls.append(("open", parent, name, kwargs))
        return 2 if kwargs["directory"] is True else 3

    def metadata(self, handle: int) -> data_root_handle_module.EntryMetadata:
        return self.metadata_by_handle[handle]

    def into_fd(self, handle: int, flags: int) -> int:
        self.calls.append(("into_fd", handle, flags))
        return handle

    def from_fd(self, descriptor: int) -> int:
        self.calls.append(("from_fd", descriptor))
        return descriptor

    def rename(self, handle: int, root: int | None, destination: str) -> None:
        self.calls.append(("rename", handle, root, destination))

    def close(self, handle: int) -> None:
        self.calls.append(("close", handle))


class _RenamePrefix(ctypes.Structure):
    _fields_ = [
        ("replace_if_exists", ctypes.c_ubyte),
        ("root_directory", ctypes.c_void_p),
        ("file_name_length", ctypes.c_uint32),
    ]


class _FakeNtdll:
    def __init__(self) -> None:
        self.calls: list[tuple[int, int | None, int, int, int]] = []

    def NtSetInformationFile(
        self,
        handle: ctypes.c_void_p,
        _io_status: object,
        information: object,
        information_size: int,
        information_class: int,
    ) -> int:
        prefix = ctypes.cast(information, ctypes.POINTER(_RenamePrefix)).contents
        self.calls.append(
            (
                int(handle.value or 0),
                prefix.root_directory,
                int(prefix.file_name_length),
                information_size,
                information_class,
            )
        )
        return 0


def test_o4cp_windows_backend_uses_atomic_relative_create_and_publish(tmp_path: Path) -> None:
    api = _FakeWindowsApi()
    root = data_root_windows_module._WindowsRootHandle(
        tmp_path,
        1,
        (7, 1),
        api,  # type: ignore[arg-type]
    )

    assert root.create_directory(PurePosixPath("nested"), 0o700) == (7, 2)
    descriptor = root.open_file(
        PurePosixPath("temporary"),
        os.O_RDONLY,
        expected_identity=(7, 3),
        for_publication=True,
    )
    root.publish(
        PurePosixPath("temporary"),
        PurePosixPath("snapshot.shisad-backup"),
        expected_identity=(7, 3),
        verified_descriptor=descriptor,
    )

    create_call = api.calls[0]
    assert create_call[:3] == ("open", 1, "nested")
    assert create_call[3]["disposition"] == data_root_windows_module._FILE_CREATE
    assert create_call[3]["directory"] is True
    publish_open = next(call for call in api.calls if call[:3] == ("open", 1, "temporary"))
    assert int(publish_open[3]["desired_access"]) & data_root_windows_module._DELETE
    assert publish_open[3]["share_delete"] is False
    assert ("from_fd", 3) in api.calls
    assert ("rename", 3, 1, "snapshot.shisad-backup") in api.calls
    assert len([call for call in api.calls if call[:3] == ("open", 1, "temporary")]) == 1


def test_o4cp_windows_native_rename_uses_rooted_nt_information() -> None:
    api = object.__new__(data_root_windows_module._WindowsNativeApi)
    ntdll = _FakeNtdll()
    api._ntdll = ntdll

    api.rename(3, 1, "x")

    assert len(ntdll.calls) == 1
    handle, root, name_length, information_size, information_class = ntdll.calls[0]
    assert (handle, root) == (3, 1)
    assert name_length == len("x".encode("utf-16-le"))
    assert information_size >= ctypes.sizeof(_RenamePrefix) + name_length
    assert information_class == data_root_windows_module._FILE_RENAME_INFORMATION_CLASS


def test_o4cp_windows_file_reads_request_synchronous_handle_access(tmp_path: Path) -> None:
    api = _FakeWindowsApi()
    root = data_root_windows_module._WindowsRootHandle(
        tmp_path,
        1,
        (7, 1),
        api,  # type: ignore[arg-type]
    )

    descriptor = root.open_file(
        PurePosixPath("state.json"),
        os.O_RDONLY,
        expected_identity=(7, 3),
    )

    assert descriptor == 3
    open_call = next(call for call in api.calls if call[:3] == ("open", 1, "state.json"))
    desired_access = int(open_call[3]["desired_access"])
    assert desired_access & data_root_windows_module._GENERIC_READ
    assert desired_access & data_root_windows_module._SYNCHRONIZE


@_POSIX_ONLY
def test_o4cp_root_handle_rejects_root_path_replacement(tmp_path: Path) -> None:
    root_path = tmp_path / "root"
    root_path.mkdir()
    displaced = tmp_path / "displaced"
    replacement = tmp_path / "replacement"
    replacement.mkdir()

    with open_root(root_path) as root:
        root_path.rename(displaced)
        root_path.symlink_to(replacement, target_is_directory=True)

        with pytest.raises(RootHandleError, match=r"identity|replaced"):
            root.require_path_identity()


@_POSIX_ONLY
def test_o4cp_root_handle_never_follows_replaced_intermediate(
    tmp_path: Path,
) -> None:
    root_path = tmp_path / "root"
    target = root_path / "sessions" / "state.json"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"bound-state")
    displaced = tmp_path / "displaced-sessions"

    with open_root(root_path) as root:
        expected = root.metadata(PurePosixPath("sessions/state.json")).identity
        (root_path / "sessions").rename(displaced)
        (root_path / "sessions").symlink_to(displaced, target_is_directory=True)

        with pytest.raises(RootHandleError, match=r"link|unsafe|component"):
            root.open_file(
                PurePosixPath("sessions/state.json"),
                os.O_RDONLY,
                expected_identity=expected,
            )


@_POSIX_ONLY
def test_drh1_open_child_directory_stays_bound_after_name_replacement(
    tmp_path: Path,
) -> None:
    root_path = tmp_path / "root"
    nested = root_path / "sessions"
    nested.mkdir(parents=True)
    (nested / "state.json").write_bytes(b"bound-state")
    displaced = tmp_path / "displaced-sessions"

    with (
        open_root(root_path) as root,
        root.open_child_directory(
            PurePosixPath("sessions"),
            expected_identity=root.metadata(PurePosixPath("sessions")).identity,
        ) as child,
    ):
        nested.rename(displaced)
        nested.mkdir()
        (nested / "state.json").write_bytes(b"replacement-state")

        descriptor = child.open_file(PurePosixPath("state.json"), os.O_RDONLY)
        with os.fdopen(descriptor, "rb") as source:
            assert source.read() == b"bound-state"
        with pytest.raises(RootHandleError, match=r"identity|changed|replaced"):
            child.require_path_identity()

    assert (nested / "state.json").read_bytes() == b"replacement-state"


@_POSIX_ONLY
def test_o4cp_root_handle_creates_and_cleans_relative_entries(tmp_path: Path) -> None:
    root_path = tmp_path / "root"
    root_path.mkdir()

    with open_root(root_path) as root:
        directory_identity = root.create_directory(PurePosixPath("nested"), 0o700)
        descriptor = root.create_file(PurePosixPath("nested/state.json"), 0o600)
        with os.fdopen(descriptor, "wb") as target:
            target.write(b"state")
            target.flush()
            os.fsync(target.fileno())
        file_identity = root.metadata(PurePosixPath("nested/state.json")).identity

        root.unlink(PurePosixPath("nested/state.json"), expected_identity=file_identity)
        root.rmdir(PurePosixPath("nested"), expected_identity=directory_identity)

    assert list(root_path.iterdir()) == []


@_POSIX_ONLY
def test_o4cp_root_handle_publishes_verified_sibling_exclusively(tmp_path: Path) -> None:
    parent = tmp_path / "archives"
    parent.mkdir()

    with open_root(parent) as root:
        descriptor = root.create_file(PurePosixPath("temporary"), 0o600)
        with os.fdopen(descriptor, "wb") as target:
            target.write(b"verified")
            target.flush()
            os.fsync(target.fileno())
        identity = root.metadata(PurePosixPath("temporary")).identity
        descriptor = root.open_file(
            PurePosixPath("temporary"), os.O_RDONLY, expected_identity=identity
        )
        try:
            root.publish(
                PurePosixPath("temporary"),
                PurePosixPath("snapshot.shisad-backup"),
                expected_identity=identity,
                verified_descriptor=descriptor,
            )
        finally:
            os.close(descriptor)

    assert (parent / "snapshot.shisad-backup").read_bytes() == b"verified"
    assert not (parent / "temporary").exists()

    with open_root(parent) as root, pytest.raises(FileExistsError):
        descriptor = root.create_file(PurePosixPath("temporary"), 0o600)
        os.close(descriptor)
        identity = root.metadata(PurePosixPath("temporary")).identity
        descriptor = root.open_file(
            PurePosixPath("temporary"), os.O_RDONLY, expected_identity=identity
        )
        try:
            root.publish(
                PurePosixPath("temporary"),
                PurePosixPath("snapshot.shisad-backup"),
                expected_identity=identity,
                verified_descriptor=descriptor,
            )
        finally:
            os.close(descriptor)


@_POSIX_ONLY
def test_drh1_publication_mismatch_never_deletes_the_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent = tmp_path / "archives"
    parent.mkdir()
    destination = PurePosixPath("snapshot.shisad-backup")

    with open_root(parent) as root:
        descriptor = root.create_file(PurePosixPath("temporary"), 0o600)
        with os.fdopen(descriptor, "wb") as target:
            target.write(b"verified")
        expected = root.metadata(PurePosixPath("temporary")).identity
        descriptor = root.open_file(
            PurePosixPath("temporary"), os.O_RDONLY, expected_identity=expected
        )
        original_metadata = root.metadata
        replaced = False

        def replace_published_name(relative: PurePosixPath) -> object:
            nonlocal replaced
            if relative == destination and not replaced:
                (parent / destination.name).unlink()
                (parent / destination.name).write_bytes(b"replacement")
                replaced = True
            return original_metadata(relative)

        monkeypatch.setattr(root, "metadata", replace_published_name)
        try:
            with pytest.raises(RootHandleError, match=r"verified|published|identity"):
                root.publish(
                    PurePosixPath("temporary"),
                    destination,
                    expected_identity=expected,
                    verified_descriptor=descriptor,
                )
        finally:
            os.close(descriptor)

    assert replaced
    assert (parent / destination.name).read_bytes() == b"replacement"


@_POSIX_ONLY
def test_o4cp_root_handle_refuses_missing_posix_capability(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root_path = tmp_path / "root"
    root_path.mkdir()
    monkeypatch.setattr(os, "supports_dir_fd", set())

    with (
        pytest.raises(RootHandleError, match=r"root-relative|unavailable"),
        open_root(root_path),
    ):
        pass


@_WINDOWS_ONLY
def test_o4cp_windows_root_handle_round_trip_and_exclusive_publication(tmp_path: Path) -> None:
    root_path = tmp_path / "root"
    root_path.mkdir(mode=0o700)

    with open_root(root_path) as root:
        directory_identity = root.create_directory(PurePosixPath("nested"), 0o700)
        with root.open_child_directory(
            PurePosixPath("nested"), expected_identity=directory_identity
        ) as child:
            descriptor = child.create_file(PurePosixPath("state.json"), 0o600)
            with os.fdopen(descriptor, "wb") as target:
                target.write(b"windows-rooted-state")
                target.flush()
                os.fsync(target.fileno())
            file_identity = child.metadata(PurePosixPath("state.json")).identity
            descriptor = child.open_file(
                PurePosixPath("state.json"),
                os.O_RDONLY,
                expected_identity=file_identity,
            )
            with os.fdopen(descriptor, "rb") as source:
                assert source.read() == b"windows-rooted-state"
            child.unlink(PurePosixPath("state.json"), expected_identity=file_identity)

        temporary = PurePosixPath("temporary")
        descriptor = root.create_file(temporary, 0o600)
        with os.fdopen(descriptor, "wb") as target:
            target.write(b"published")
        temporary_identity = root.metadata(temporary).identity
        descriptor = root.open_file(
            temporary,
            os.O_RDONLY,
            expected_identity=temporary_identity,
            for_publication=True,
        )
        try:
            root.publish(
                temporary,
                PurePosixPath("snapshot.shisad-backup"),
                expected_identity=temporary_identity,
                verified_descriptor=descriptor,
            )
        finally:
            os.close(descriptor)

        root.rmdir(PurePosixPath("nested"), expected_identity=directory_identity)

    assert (root_path / "snapshot.shisad-backup").read_bytes() == b"published"
