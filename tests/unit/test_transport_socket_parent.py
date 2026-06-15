"""Control socket parent directory hardening."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

import shisad.core.api.transport as transport
from shisad.core.api.transport import ControlServer


@pytest.mark.asyncio
async def test_gh50_control_server_hardens_default_tmp_socket_parent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    socket_parent = tmp_path / "shisad-default"
    socket_parent.mkdir()
    socket_parent.chmod(0o777)
    monkeypatch.setattr(transport, "_default_tmp_socket_parent", lambda: socket_parent)

    server = ControlServer(socket_parent / "control.sock")
    try:
        await server.start()
        assert stat.S_IMODE(socket_parent.lstat().st_mode) == 0o700
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_gh50_control_server_rejects_unowned_default_tmp_socket_parent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    socket_parent = tmp_path / "shisad-default"
    socket_parent.mkdir()
    monkeypatch.setattr(transport, "_default_tmp_socket_parent", lambda: socket_parent)
    monkeypatch.setattr(transport, "_current_euid", lambda: os.getuid() + 1)

    server = ControlServer(socket_parent / "control.sock")

    with pytest.raises(PermissionError, match="owned by uid"):
        await server.start()


@pytest.mark.asyncio
async def test_gh50_control_server_rejects_symlinked_default_tmp_socket_parent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "attacker-owned-target"
    target.mkdir()
    socket_parent = tmp_path / "shisad-default"
    socket_parent.symlink_to(target, target_is_directory=True)
    monkeypatch.setattr(transport, "_default_tmp_socket_parent", lambda: socket_parent)

    server = ControlServer(socket_parent / "control.sock")

    with pytest.raises(PermissionError, match="symlink"):
        await server.start()
