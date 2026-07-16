"""Control socket parent directory hardening."""

from __future__ import annotations

import asyncio
import os
import socket
import stat
import uuid
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
async def test_f3_control_server_rejects_owner_writable_custom_socket_parent(
    tmp_path: Path,
) -> None:
    socket_parent = tmp_path / "custom"
    socket_parent.mkdir()
    socket_parent.chmod(0o777)
    server = ControlServer(socket_parent / "control.sock")

    with pytest.raises(PermissionError, match="mode 0777"):
        await server.start()

    assert stat.S_IMODE(socket_parent.lstat().st_mode) == 0o777
    assert not (socket_parent / "control.sock").exists()


@pytest.mark.asyncio
async def test_f3_control_server_rejects_writable_custom_socket_ancestor(
    tmp_path: Path,
) -> None:
    writable_ancestor = tmp_path / "writable"
    writable_ancestor.mkdir()
    writable_ancestor.chmod(0o777)
    socket_parent = writable_ancestor / "private"
    socket_parent.mkdir(mode=0o700)
    server = ControlServer(socket_parent / "control.sock")

    with pytest.raises(PermissionError, match="mode 0777"):
        await server.start()

    assert not (socket_parent / "control.sock").exists()


@pytest.mark.asyncio
async def test_f3_control_client_rejects_owner_writable_custom_socket_parent(
    tmp_path: Path,
) -> None:
    socket_parent = tmp_path / "custom"
    socket_parent.mkdir()
    socket_parent.chmod(0o777)
    socket_path = socket_parent / "control.sock"
    socket_path.write_text("spoof", encoding="utf-8")
    client = ControlClient(socket_path)

    with pytest.raises(PermissionError, match="mode 0777"):
        await client.connect()

    assert stat.S_IMODE(socket_parent.lstat().st_mode) == 0o777


@pytest.mark.asyncio
async def test_f3_control_client_rejects_writable_custom_socket_ancestor(
    tmp_path: Path,
) -> None:
    writable_ancestor = tmp_path / "writable-client"
    writable_ancestor.mkdir()
    writable_ancestor.chmod(0o777)
    socket_parent = writable_ancestor / "private"
    socket_parent.mkdir(mode=0o700)
    socket_path = socket_parent / "control.sock"
    socket_path.write_text("spoof", encoding="utf-8")
    client = ControlClient(socket_path)

    with pytest.raises(PermissionError, match="mode 0777"):
        await client.connect()


@pytest.mark.asyncio
async def test_f3_control_client_rejects_unowned_server_peer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    socket_path = tmp_path / "control.sock"

    async def _close_peer(
        _reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_unix_server(_close_peer, path=socket_path)
    monkeypatch.setattr(
        ControlServer,
        "_get_peer_credentials",
        staticmethod(
            lambda _writer: transport.PeerCredentials(
                uid=os.getuid() + 1,
            )
        ),
    )
    client = ControlClient(socket_path)
    try:
        with pytest.raises(PermissionError, match="server peer owned by uid"):
            await client.connect()
    finally:
        await client.close()
        server.close()
        await server.wait_closed()
        socket_path.unlink(missing_ok=True)


def _report_directory_as_foreign_owned(
    directory: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity = directory.stat()
    original_fstat = os.fstat

    def _foreign_directory_fstat(fd: int) -> os.stat_result:
        result = original_fstat(fd)
        if (result.st_dev, result.st_ino) != (identity.st_dev, identity.st_ino):
            return result
        values = list(result)
        values[4] = os.getuid() + 1
        return os.stat_result(values)

    monkeypatch.setattr(transport.os, "fstat", _foreign_directory_fstat)


def test_f3_arbitrary_socket_path_rejects_foreign_owned_sticky_parent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    shared_parent = tmp_path / "shared"
    shared_parent.mkdir()
    shared_parent.chmod(0o1777)
    _report_directory_as_foreign_owned(shared_parent, monkeypatch)

    with pytest.raises(PermissionError, match="owned by uid"):
        transport._ensure_socket_parent(shared_parent / "control.sock")

    with pytest.raises(PermissionError, match="owned by uid"):
        transport._validate_socket_parent(shared_parent / "control.sock")


def test_f3_arbitrary_socket_path_rejects_foreign_owned_intermediate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    foreign_ancestor = tmp_path / "foreign"
    foreign_ancestor.mkdir(mode=0o755)
    socket_parent = foreign_ancestor / "private"
    socket_parent.mkdir(mode=0o700)
    _report_directory_as_foreign_owned(foreign_ancestor, monkeypatch)

    with pytest.raises(PermissionError, match="owned by uid"):
        transport._ensure_socket_parent(socket_parent / "control.sock")

    with pytest.raises(PermissionError, match="owned by uid"):
        transport._validate_socket_parent(socket_parent / "control.sock")


@pytest.mark.parametrize("operation", ["ensure", "validate"])
def test_f3_xdg_socket_path_rejects_foreign_owned_intermediate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
) -> None:
    foreign_ancestor = tmp_path / "foreign"
    foreign_ancestor.mkdir(mode=0o755)
    runtime_dir = foreign_ancestor / "runtime"
    runtime_dir.mkdir(mode=0o700)
    socket_parent = runtime_dir / "shisad"
    if operation == "validate":
        socket_parent.mkdir(mode=0o700)
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(runtime_dir))
    _report_directory_as_foreign_owned(foreign_ancestor, monkeypatch)
    socket_path = socket_parent / "control.sock"

    with pytest.raises(PermissionError, match="owned by uid"):
        if operation == "ensure":
            transport._ensure_socket_parent(socket_path)
        else:
            transport._validate_socket_parent(socket_path)


def test_f3_arbitrary_socket_path_rejects_foreign_owned_nonsticky_parent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    shared_parent = tmp_path / "shared"
    shared_parent.mkdir()
    shared_parent.chmod(0o777)
    monkeypatch.setattr(transport, "_current_euid", lambda: os.getuid() + 1)

    with pytest.raises(PermissionError, match="owned by uid"):
        transport._ensure_socket_parent(shared_parent / "control.sock")


@pytest.mark.asyncio
async def test_f3_control_server_supports_documented_direct_tmp_socket() -> None:
    tmp_parent = Path("/tmp")
    tmp_stat = tmp_parent.lstat()
    if tmp_stat.st_uid == os.geteuid():
        pytest.skip("/tmp is owned by the test user; synthetic sticky-parent coverage applies")
    assert stat.S_IMODE(tmp_stat.st_mode) & stat.S_ISVTX
    socket_path = tmp_parent / f"shisad-f3-{os.getpid()}-{uuid.uuid4().hex}.sock"
    server = ControlServer(socket_path)
    try:
        await server.start()
        assert stat.S_ISSOCK(socket_path.lstat().st_mode)
        assert stat.S_IMODE(socket_path.lstat().st_mode) == 0o600
    finally:
        if server._server is not None:
            await server.stop()
        elif socket_path.exists():
            socket_path.unlink()


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
