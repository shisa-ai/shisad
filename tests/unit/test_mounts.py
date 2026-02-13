"""M3 filesystem mount policy checks."""

from __future__ import annotations

from pathlib import Path

from shisad.executors.mounts import FilesystemPolicy, MountManager, MountRule


def test_m3_mounts_allow_read_and_block_write_on_ro(tmp_path: Path) -> None:
    allowed_root = tmp_path / "workspace"
    allowed_root.mkdir(parents=True, exist_ok=True)
    target = allowed_root / "notes.txt"
    target.write_text("ok", encoding="utf-8")
    manager = MountManager(
        FilesystemPolicy(mounts=[MountRule(path=f"{allowed_root.as_posix()}/**", mode="ro")])
    )

    read_decision = manager.check_access(str(target), write=False)
    write_decision = manager.check_access(str(target), write=True)

    assert read_decision.allowed is True
    assert write_decision.allowed is False
    assert write_decision.reason == "read_only_mount"


def test_m3_mounts_denylist_overrides_mount_allowlist(tmp_path: Path) -> None:
    root = tmp_path / "workspace"
    root.mkdir(parents=True, exist_ok=True)
    secret = root / "id_rsa.pem"
    secret.write_text("private", encoding="utf-8")
    manager = MountManager(
        FilesystemPolicy(
            mounts=[MountRule(path=f"{root.as_posix()}/**", mode="rw")],
            denylist=["**/*.pem"],
        )
    )
    decision = manager.check_access(str(secret), write=False)
    assert decision.allowed is False
    assert decision.reason == "denylist_match"


def test_m3_mounts_block_outside_mounts(tmp_path: Path) -> None:
    mounted = tmp_path / "mounted"
    outside = tmp_path / "outside"
    mounted.mkdir(parents=True, exist_ok=True)
    outside.mkdir(parents=True, exist_ok=True)
    file_outside = outside / "data.txt"
    file_outside.write_text("x", encoding="utf-8")

    manager = MountManager(
        FilesystemPolicy(mounts=[MountRule(path=f"{mounted.as_posix()}/**", mode="ro")])
    )
    decision = manager.check_access(str(file_outside), write=False)
    assert decision.allowed is False
    assert decision.reason == "outside_mounts"
