"""Control socket parent directory hardening."""

from __future__ import annotations

import asyncio
import os
import socket
import stat
from pathlib import Path

import pytest

import shisad.core.api.transport as transport
from shisad.core.api.transport import ControlClient, ControlServer


def test_gh50_transport_ignores_tilde_xdg_runtime_dir(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("XDG_RUNTIME_DIR", "~/runtime")

    assert transport._configured_xdg_runtime_dir() is None


def test_gh50_transport_ignores_leading_whitespace_xdg_runtime_dir(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("XDG_RUNTIME_DIR", " /tmp/runtime")

    assert transport._configured_xdg_runtime_dir() is None


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


@pytest.mark.asyncio
async def test_gh50_control_client_rejects_symlinked_default_tmp_socket_parent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "attacker-owned-target"
    target.mkdir()
    socket_parent = tmp_path / "shisad-default"
    socket_parent.symlink_to(target, target_is_directory=True)
    monkeypatch.setattr(transport, "_default_tmp_socket_parent", lambda: socket_parent)

    client = ControlClient(socket_parent / "control.sock")

    with pytest.raises(PermissionError, match="symlink"):
        await client.connect()


@pytest.mark.asyncio
async def test_gh50_control_client_rejects_world_writable_default_tmp_socket_parent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    socket_parent = tmp_path / "shisad-default"
    socket_parent.mkdir()
    socket_parent.chmod(0o777)
    (socket_parent / "control.sock").write_text("spoof", encoding="utf-8")
    monkeypatch.setattr(transport, "_default_tmp_socket_parent", lambda: socket_parent)

    client = ControlClient(socket_parent / "control.sock")

    with pytest.raises(PermissionError, match="mode 0777"):
        await client.connect()
    assert stat.S_IMODE(socket_parent.lstat().st_mode) == 0o777


@pytest.mark.asyncio
async def test_f3_control_server_does_not_unlink_active_socket(tmp_path: Path) -> None:
    socket_path = tmp_path / "control.sock"
    first = ControlServer(socket_path)
    second = ControlServer(socket_path)
    await first.start()
    first_identity = socket_path.stat().st_dev, socket_path.stat().st_ino
    try:
        with pytest.raises(OSError, match="already active"):
            await second.start()
        assert (socket_path.stat().st_dev, socket_path.stat().st_ino) == first_identity
        reader, writer = await asyncio.open_unix_connection(socket_path)
        writer.close()
        await writer.wait_closed()
        del reader
    finally:
        if second._server is not None:
            await second.stop()
        await first.stop()


@pytest.mark.asyncio
async def test_f3_control_server_creates_arbitrary_socket_parents_owner_only(
    tmp_path: Path,
) -> None:
    socket_path = tmp_path / "new" / "nested" / "control.sock"
    server = ControlServer(socket_path)
    previous_umask = os.umask(0)
    try:
        await server.start()
    finally:
        os.umask(previous_umask)
    try:
        assert stat.S_IMODE((tmp_path / "new").stat().st_mode) == 0o700
        assert stat.S_IMODE(socket_path.parent.stat().st_mode) == 0o700
        assert stat.S_IMODE(socket_path.stat().st_mode) == 0o600
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_f3_control_server_replaces_owned_stale_socket(tmp_path: Path) -> None:
    socket_path = tmp_path / "control.sock"
    stale = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    stale.bind(str(socket_path))
    stale.close()

    server = ControlServer(socket_path)
    try:
        await server.start()
        assert stat.S_ISSOCK(socket_path.stat().st_mode)
        reader, writer = await asyncio.open_unix_connection(socket_path)
        writer.close()
        await writer.wait_closed()
        del reader
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_f3_control_server_rejects_non_socket_without_unlink(tmp_path: Path) -> None:
    socket_path = tmp_path / "control.sock"
    socket_path.write_text("do not remove", encoding="utf-8")
    before = socket_path.stat()
    server = ControlServer(socket_path)
    try:
        with pytest.raises(OSError, match="not a socket"):
            await server.start()
        after = socket_path.stat()
        assert (after.st_dev, after.st_ino, socket_path.read_text(encoding="utf-8")) == (
            before.st_dev,
            before.st_ino,
            "do not remove",
        )
    finally:
        if server._server is not None:
            await server.stop()


@pytest.mark.asyncio
async def test_f3_delayed_stop_does_not_unlink_successor_socket(tmp_path: Path) -> None:
    socket_path = tmp_path / "control.sock"
    old = ControlServer(socket_path)
    successor = ControlServer(socket_path)
    await old.start()
    assert old._server is not None
    old._server.close()
    await old._server.wait_closed()
    old._server = None
    socket_path.unlink()
    await successor.start()
    successor_identity = socket_path.stat().st_dev, socket_path.stat().st_ino
    try:
        await old.stop()
        assert (socket_path.stat().st_dev, socket_path.stat().st_ino) == successor_identity
        reader, writer = await asyncio.open_unix_connection(socket_path)
        writer.close()
        await writer.wait_closed()
        del reader
    finally:
        await successor.stop()
        await old.stop()
