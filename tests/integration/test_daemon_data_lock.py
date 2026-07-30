"""F3 lifetime data-root writer ownership integration coverage."""

from __future__ import annotations

import asyncio
from contextlib import suppress
from pathlib import Path

import pytest
from filelock import FileLock, SoftFileLock, Timeout

import shisad.daemon.services as services_module
from shisad.channels.base import InMemoryChannel
from shisad.channels.telegram import TelegramChannel
from shisad.core.api.transport import ControlClient
from shisad.core.config import DaemonConfig
from shisad.daemon.runner import run_daemon
from shisad.daemon.services import DaemonServices
from tests.helpers.daemon import clear_remote_provider_env, wait_for_socket


def test_filelock_zero_timeout_is_portable_and_reacquirable(tmp_path: Path) -> None:
    first = FileLock(str(tmp_path / "portable.lock"), timeout=0)
    second = FileLock(str(tmp_path / "portable.lock"), timeout=0)
    first.acquire(timeout=0)
    try:
        with pytest.raises(Timeout):
            second.acquire(timeout=0)
    finally:
        first.release()
    second.acquire(timeout=0)
    second.release()


@pytest.mark.asyncio
async def test_data_root_lock_error_is_redacted_before_service_construction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _BrokenLock:
        def acquire(self, *, timeout: float) -> None:
            raise PermissionError(f"denied: {tmp_path / 'private-data'}")

    config = _config(tmp_path, root="private-data", socket_name="control.sock")
    monkeypatch.setattr(
        services_module,
        "FileLock",
        lambda *_args, **_kwargs: _BrokenLock(),
    )

    with pytest.raises(RuntimeError, match="lock could not be acquired") as raised:
        await DaemonServices.build(config)

    assert str(config.data_dir) not in str(raised.value)
    assert config.data_dir.exists()
    assert list(config.data_dir.iterdir()) == []


@pytest.mark.asyncio
async def test_soft_lock_fallback_is_not_left_as_a_false_held_artifact(tmp_path: Path) -> None:
    services = object.__new__(DaemonServices)
    data_lock = SoftFileLock(str(tmp_path / "soft.lock"), timeout=0)
    data_lock.acquire(timeout=0)
    services.data_lock = data_lock

    await DaemonServices.shutdown(services)

    assert data_lock.is_locked is False
    assert Path(data_lock.lock_file).exists() is False


def _config(tmp_path: Path, *, root: str, socket_name: str, **overrides: object) -> DaemonConfig:
    return DaemonConfig(
        data_dir=tmp_path / root,
        socket_path=tmp_path / socket_name,
        policy_path=tmp_path / f"{root}.policy.yaml",
        log_level="INFO",
        **overrides,
    )


async def _stop(task: asyncio.Task[None], client: ControlClient) -> None:
    with suppress(Exception):
        await client.call("daemon.shutdown")
    await client.close()
    await asyncio.wait_for(task, timeout=5)


@pytest.mark.asyncio
async def test_same_data_root_loser_fails_before_endpoint_or_store_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clear_remote_provider_env(monkeypatch)
    first_config = _config(tmp_path, root="shared", socket_name="first.sock")
    loser_config = _config(tmp_path, root="shared", socket_name="loser.sock")
    first_task = asyncio.create_task(run_daemon(first_config))
    first_client = ControlClient(first_config.socket_path)

    try:
        await wait_for_socket(first_config.socket_path)
        await first_client.connect()
        before = {
            path.relative_to(first_config.data_dir): path.read_bytes()
            for path in first_config.data_dir.rglob("*")
            if path.is_file()
        }

        with pytest.raises(RuntimeError, match=r"data.*(locked|in use|owned)") as raised:
            await asyncio.wait_for(run_daemon(loser_config), timeout=5)

        after = {
            path.relative_to(first_config.data_dir): path.read_bytes()
            for path in first_config.data_dir.rglob("*")
            if path.is_file()
        }
        assert loser_config.socket_path.exists() is False
        assert before == after
        assert str(first_config.data_dir) not in str(raised.value)
        assert (await first_client.call("daemon.status"))["status"] == "running"
    finally:
        await _stop(first_task, first_client)

    lock_artifact = first_config.data_dir / ".shisad.lock"
    assert lock_artifact.exists()

    restart_task = asyncio.create_task(run_daemon(loser_config))
    restart_client = ControlClient(loser_config.socket_path)
    try:
        await wait_for_socket(loser_config.socket_path)
        await restart_client.connect()
        assert (await restart_client.call("daemon.status"))["status"] == "running"
    finally:
        await _stop(restart_task, restart_client)


@pytest.mark.asyncio
async def test_disjoint_data_roots_with_disjoint_endpoints_run_concurrently(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clear_remote_provider_env(monkeypatch)
    first_config = _config(tmp_path, root="one", socket_name="one.sock")
    second_config = _config(tmp_path, root="two", socket_name="two.sock")
    first_task = asyncio.create_task(run_daemon(first_config))
    second_task = asyncio.create_task(run_daemon(second_config))
    first_client = ControlClient(first_config.socket_path)
    second_client = ControlClient(second_config.socket_path)

    try:
        await asyncio.gather(
            wait_for_socket(first_config.socket_path),
            wait_for_socket(second_config.socket_path),
        )
        await asyncio.gather(first_client.connect(), second_client.connect())
        statuses = await asyncio.gather(
            first_client.call("daemon.status"),
            second_client.call("daemon.status"),
        )
        assert [status["status"] for status in statuses] == ["running", "running"]
    finally:
        await asyncio.gather(
            _stop(first_task, first_client),
            _stop(second_task, second_client),
        )


@pytest.mark.asyncio
async def test_partial_startup_failure_releases_data_root_lock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clear_remote_provider_env(monkeypatch)
    broken = _config(
        tmp_path,
        root="retryable",
        socket_name="broken.sock",
        matrix_enabled=True,
    )

    with pytest.raises(ValueError, match="Matrix channel is enabled"):
        await run_daemon(broken)

    healthy = _config(tmp_path, root="retryable", socket_name="healthy.sock")
    task = asyncio.create_task(run_daemon(healthy))
    client = ControlClient(healthy.socket_path)
    try:
        await wait_for_socket(healthy.socket_path)
        await client.connect()
        assert (await client.call("daemon.status"))["status"] == "running"
    finally:
        await _stop(task, client)


@pytest.mark.asyncio
async def test_gh111_telegram_timeout_starts_degraded_and_releases_lock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clear_remote_provider_env(monkeypatch)
    connect_cancelled = asyncio.Event()

    async def _blocked_connect(channel: TelegramChannel) -> None:
        await InMemoryChannel.connect(channel)
        try:
            await asyncio.Event().wait()
        finally:
            connect_cancelled.set()

    monkeypatch.setattr(TelegramChannel, "connect", _blocked_connect)
    config = _config(
        tmp_path,
        root="g",
        socket_name="g.sock",
        telegram_enabled=True,
        telegram_bot_token="placeholder-not-a-real-token",
        channel_startup_timeout_seconds=0.1,
    )
    task = asyncio.create_task(run_daemon(config))
    client = ControlClient(config.socket_path)

    try:
        await wait_for_socket(config.socket_path)
        await client.connect()
        status = await client.call("daemon.status")
        assert status["status"] == "running"
        assert status["channels"]["telegram"] == {
            "enabled": True,
            "available": True,
            "connected": False,
            "startup": {
                "status": "degraded",
                "reason_code": "channel.startup_timeout",
                "timeout_seconds": 0.1,
            },
        }
        assert connect_cancelled.is_set()
    finally:
        await _stop(task, client)

    probe = FileLock(str(config.data_dir / ".shisad.lock"), timeout=0)
    probe.acquire(timeout=0)
    probe.release()


@pytest.mark.asyncio
async def test_gh111_uncleanable_channel_fails_bounded_and_releases_lock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clear_remote_provider_env(monkeypatch)

    async def _blocked_connect(channel: TelegramChannel) -> None:
        await InMemoryChannel.connect(channel)
        await asyncio.Event().wait()

    async def _blocked_disconnect(_channel: TelegramChannel) -> None:
        await asyncio.Event().wait()

    monkeypatch.setattr(TelegramChannel, "connect", _blocked_connect)
    monkeypatch.setattr(TelegramChannel, "disconnect_strict", _blocked_disconnect)
    config = _config(
        tmp_path,
        root="u",
        socket_name="u.sock",
        telegram_enabled=True,
        telegram_bot_token="placeholder-not-a-real-token",
        channel_startup_timeout_seconds=0.1,
    )

    with pytest.raises(RuntimeError, match="telegram channel startup cleanup timed out"):
        await asyncio.wait_for(run_daemon(config), timeout=1.0)

    assert config.socket_path.exists() is False
    probe = FileLock(str(config.data_dir / ".shisad.lock"), timeout=0)
    probe.acquire(timeout=0)
    probe.release()
