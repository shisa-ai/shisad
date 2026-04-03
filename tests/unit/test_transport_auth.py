"""Control API peer credential authorization checks."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from shisad.core.api.transport import ControlServer, PeerCredentials
from shisad.daemon.context import RequestContext


def test_admin_peer_accepts_current_uid() -> None:
    peer = PeerCredentials(pid=1, uid=os.getuid(), gid=os.getgid())
    assert ControlServer._is_admin_peer(peer)


def test_admin_peer_rejects_unknown_uid() -> None:
    peer = PeerCredentials()
    assert not ControlServer._is_admin_peer(peer)


def test_admin_peer_rejects_other_uid() -> None:
    other_uid = os.getuid() + 1
    peer = PeerCredentials(pid=1, uid=other_uid, gid=os.getgid())
    assert not ControlServer._is_admin_peer(peer)


@pytest.mark.asyncio
async def test_admin_only_method_rejects_non_admin_peer(tmp_path: Path) -> None:
    server = ControlServer(socket_path=tmp_path / "sock")

    async def handler(params: object, ctx: RequestContext) -> dict[str, str]:
        _ = (params, ctx)
        return {"ok": "yes"}

    server.register_method("session.grant_capabilities", handler, admin_only=True)

    request = {
        "jsonrpc": "2.0",
        "method": "session.grant_capabilities",
        "params": {"session_id": "s1", "capabilities": ["http.request"]},
        "id": 1,
    }
    raw = json.dumps(request).encode("utf-8")
    non_admin_peer = PeerCredentials(pid=1, uid=os.getuid() + 1, gid=os.getgid())
    response = await server._process_message(raw, non_admin_peer)

    assert "Permission denied" in response


@pytest.mark.asyncio
async def test_peer_authorizer_rejects_mismatched_pid(tmp_path: Path) -> None:
    server = ControlServer(
        socket_path=tmp_path / "sock",
        peer_authorizer=lambda _method, peer: peer.pid == 1234,
    )

    async def handler(params: object, ctx: RequestContext) -> dict[str, str]:
        _ = (params, ctx)
        return {"ok": "yes"}

    server.register_method("control_plane.ping", handler)

    request = {
        "jsonrpc": "2.0",
        "method": "control_plane.ping",
        "params": {},
        "id": 7,
    }
    raw = json.dumps(request).encode("utf-8")
    unauthorized_peer = PeerCredentials(pid=4321, uid=os.getuid(), gid=os.getgid())
    response = await server._process_message(raw, unauthorized_peer)

    assert "Permission denied" in response
