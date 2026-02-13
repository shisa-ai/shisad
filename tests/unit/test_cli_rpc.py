"""Unit tests for shared CLI RPC helpers."""

from __future__ import annotations

from pathlib import Path
from typing import ClassVar

import click
import pytest

from shisad.cli import rpc
from shisad.core.api.schema import SessionCreateResult
from shisad.core.config import DaemonConfig


def _config(tmp_path: Path) -> DaemonConfig:
    return DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
    )


@pytest.mark.asyncio
async def test_rpc_client_context_manager_connects_and_closes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []

    class _FakeClient:
        def __init__(self, socket_path: Path) -> None:
            self.socket_path = socket_path

        async def connect(self) -> None:
            events.append("connect")

        async def close(self) -> None:
            events.append("close")

    monkeypatch.setattr(rpc, "ControlClient", _FakeClient)
    config = _config(tmp_path)

    async with rpc.rpc_client(config):
        assert events == ["connect"]

    assert events == ["connect", "close"]


def test_rpc_call_validates_response_model_and_reconnects(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, dict[str, object]]] = []

    class _FakeClient:
        instances: ClassVar[list[_FakeClient]] = []

        def __init__(self, socket_path: Path) -> None:
            self.socket_path = socket_path
            self.connected = False
            self.closed = False
            self.__class__.instances.append(self)

        async def connect(self) -> None:
            self.connected = True

        async def close(self) -> None:
            self.closed = True

        async def call(
            self,
            method: str,
            params: dict[str, object] | None = None,
        ) -> dict[str, str]:
            calls.append((method, params or {}))
            return {"session_id": f"s-{len(calls)}"}

    monkeypatch.setattr(rpc, "ControlClient", _FakeClient)
    config = _config(tmp_path)

    first = rpc.rpc_call(
        config,
        "session.create",
        {"user_id": "alice"},
        response_model=SessionCreateResult,
    )
    second = rpc.rpc_call(
        config,
        "session.create",
        {"user_id": "bob"},
        response_model=SessionCreateResult,
    )

    assert first.session_id == "s-1"
    assert second.session_id == "s-2"
    assert calls == [
        ("session.create", {"user_id": "alice"}),
        ("session.create", {"user_id": "bob"}),
    ]
    assert len(_FakeClient.instances) == 2
    assert all(client.connected and client.closed for client in _FakeClient.instances)


def test_rpc_call_reports_connection_failures_with_socket_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _FailingClient:
        def __init__(self, socket_path: Path) -> None:
            self.socket_path = socket_path

        async def connect(self) -> None:
            raise OSError("connection refused")

        async def close(self) -> None:
            return None

    monkeypatch.setattr(rpc, "ControlClient", _FailingClient)
    config = _config(tmp_path)

    with pytest.raises(click.ClickException, match="Unable to connect to daemon") as exc:
        rpc.rpc_call(config, "daemon.status", response_model=SessionCreateResult)

    assert str(config.socket_path) in str(exc.value)


def test_rpc_run_wraps_operation_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _FakeClient:
        def __init__(self, socket_path: Path) -> None:
            self.socket_path = socket_path

        async def connect(self) -> None:
            return None

        async def close(self) -> None:
            return None

    async def _operation(_client: object) -> None:
        raise RuntimeError("boom")

    monkeypatch.setattr(rpc, "ControlClient", _FakeClient)
    config = _config(tmp_path)

    with pytest.raises(click.ClickException, match=r"events\.subscribe failed: boom"):
        rpc.rpc_run(config, _operation, action="events.subscribe")
