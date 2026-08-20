"""O4C-P rooted filesystem capability contracts."""

from __future__ import annotations

import os
from pathlib import Path, PurePosixPath

import pytest

import shisad.core.data_root_handle as data_root_handle_module
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

    def rename(self, handle: int, root: int, destination: str) -> None:
        self.calls.append(("rename", handle, root, destination))

    def close(self, handle: int) -> None:
        self.calls.append(("close", handle))


def test_o4cp_windows_backend_uses_atomic_relative_create_and_publish(tmp_path: Path) -> None:
    api = _FakeWindowsApi()
    root = data_root_handle_module._WindowsRootHandle(
        tmp_path,
        1,
        (7, 1),
        api,  # type: ignore[arg-type]
    )

    assert root.create_directory(PurePosixPath("nested"), 0o700) == (7, 2)
    root.publish(
        PurePosixPath("temporary"),
        PurePosixPath("snapshot.shisad-backup"),
        expected_identity=(7, 3),
    )

    create_call = api.calls[0]
    assert create_call[:3] == ("open", 1, "nested")
    assert create_call[3]["disposition"] == data_root_handle_module._FILE_CREATE
    assert create_call[3]["directory"] is True
    publish_open = next(call for call in api.calls if call[:3] == ("open", 1, "temporary"))
    assert publish_open[3]["share_delete"] is True
    assert ("rename", 3, 1, "snapshot.shisad-backup") in api.calls


def test_o4cp_windows_file_reads_request_synchronous_handle_access(tmp_path: Path) -> None:
    api = _FakeWindowsApi()
    root = data_root_handle_module._WindowsRootHandle(
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
    assert desired_access & data_root_handle_module._GENERIC_READ
    assert desired_access & data_root_handle_module._SYNCHRONIZE


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

        root.publish(
            PurePosixPath("temporary"),
            PurePosixPath("snapshot.shisad-backup"),
            expected_identity=identity,
        )

    assert (parent / "snapshot.shisad-backup").read_bytes() == b"verified"
    assert not (parent / "temporary").exists()

    with open_root(parent) as root, pytest.raises(FileExistsError):
        descriptor = root.create_file(PurePosixPath("temporary"), 0o600)
        os.close(descriptor)
        identity = root.metadata(PurePosixPath("temporary")).identity
        root.publish(
            PurePosixPath("temporary"),
            PurePosixPath("snapshot.shisad-backup"),
            expected_identity=identity,
        )


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
        descriptor = root.create_file(PurePosixPath("nested/state.json"), 0o600)
        with os.fdopen(descriptor, "wb") as target:
            target.write(b"windows-rooted-state")
            target.flush()
            os.fsync(target.fileno())
        file_identity = root.metadata(PurePosixPath("nested/state.json")).identity
        descriptor = root.open_file(
            PurePosixPath("nested/state.json"),
            os.O_RDONLY,
            expected_identity=file_identity,
        )
        with os.fdopen(descriptor, "rb") as source:
            assert source.read() == b"windows-rooted-state"

        temporary = PurePosixPath("temporary")
        descriptor = root.create_file(temporary, 0o600)
        with os.fdopen(descriptor, "wb") as target:
            target.write(b"published")
        temporary_identity = root.metadata(temporary).identity
        root.publish(
            temporary,
            PurePosixPath("snapshot.shisad-backup"),
            expected_identity=temporary_identity,
        )

        root.unlink(PurePosixPath("nested/state.json"), expected_identity=file_identity)
        root.rmdir(PurePosixPath("nested"), expected_identity=directory_identity)

    assert (root_path / "snapshot.shisad-backup").read_bytes() == b"published"
