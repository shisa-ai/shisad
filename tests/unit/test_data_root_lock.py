"""DRH1 rooted lifecycle-lock contracts."""

from __future__ import annotations

from pathlib import Path, PurePosixPath

import pytest
from filelock import FileLock, Timeout

from shisad.core.data_root_handle import open_root
from shisad.core.data_root_lock import RootedFileLock


def test_drh1_rooted_lock_interoperates_with_existing_filelock(tmp_path: Path) -> None:
    data_root = tmp_path / "data"
    data_root.mkdir()

    with open_root(data_root) as root:
        rooted = RootedFileLock(data_root, root=root, timeout=0)
        rooted.acquire(timeout=0)
        try:
            probe = FileLock(str(data_root / ".shisad.lock"), timeout=0)
            with pytest.raises(Timeout):
                probe.acquire(timeout=0)
            assert rooted.is_locked
            assert root.metadata(PurePosixPath(".shisad.lock")).identity == rooted.identity
        finally:
            rooted.release()

    assert (data_root / ".shisad.lock").is_file()
    probe = FileLock(str(data_root / ".shisad.lock"), timeout=0)
    probe.acquire(timeout=0)
    probe.release()


def test_drh1_rooted_lock_rejects_child_replacement_after_os_lock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data_root = tmp_path / "data"
    data_root.mkdir()
    displaced = tmp_path / "displaced-lock"
    replaced = False

    with open_root(data_root) as root:
        lock = RootedFileLock(data_root, root=root, timeout=0)
        original_lock_descriptor = lock._lock_descriptor

        def replace_after_lock(descriptor: int) -> None:
            nonlocal replaced
            original_lock_descriptor(descriptor)
            (data_root / ".shisad.lock").rename(displaced)
            (data_root / ".shisad.lock").write_bytes(b"replacement")
            replaced = True

        monkeypatch.setattr(lock, "_lock_descriptor", replace_after_lock)

        with pytest.raises(OSError, match=r"identity|replaced"):
            lock.acquire(timeout=0)

        assert replaced
        assert not lock.is_locked

    assert displaced.is_file()
    assert (data_root / ".shisad.lock").read_bytes() == b"replacement"
