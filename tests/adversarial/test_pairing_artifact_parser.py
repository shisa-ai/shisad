"""Adversarial parser coverage for channel pairing request artifacts."""

from __future__ import annotations

import asyncio
from contextlib import suppress
from pathlib import Path

import pytest

from shisad.core.api.transport import ControlClient
from shisad.core.config import DaemonConfig
from shisad.daemon.runner import run_daemon


async def _wait_for_socket(path: Path, timeout: float = 2.0) -> None:
    end = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < end:
        if path.exists():
            return
        await asyncio.sleep(0.01)
    raise TimeoutError(f"Timed out waiting for socket {path}")


@pytest.fixture
def model_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SHISAD_MODEL_BASE_URL", "https://api.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_PLANNER_BASE_URL", "https://planner.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_EMBEDDINGS_BASE_URL", "https://embed.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_MONITOR_BASE_URL", "https://monitor.example.com/v1")


@pytest.mark.asyncio
async def test_m3_pairing_artifact_parser_skips_control_chars_and_malformed_lines(
    model_env: None,
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "data"
    artifact_file = data_dir / "channels" / "pairing_requests.jsonl"
    artifact_file.parent.mkdir(parents=True, exist_ok=True)
    artifact_file.write_bytes(
        b'{"channel":"discord","external_user_id":"safe-user","workspace_hint":"guild-1"}\n'
        b'{"channel":"discord","external_user_id":"null-\x00-user","workspace_hint":"guild-1"}\n'
        b'{"channel":"discord","external_user_id":"line\nbreak","workspace_hint":"guild-1"}\n'
        b'{"channel":"discord","external_user_id":"truncated"\n'
        b'["not","a","mapping"]\n'
        b'{"channel":"discord"}\n'
    )

    config = DaemonConfig(
        data_dir=data_dir,
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
        log_level="INFO",
    )
    daemon_task = asyncio.create_task(run_daemon(config))
    client = ControlClient(config.socket_path)
    try:
        await _wait_for_socket(config.socket_path)
        await client.connect()
        proposal = await client.call(
            "channel.pairing_propose",
            {"channel": "discord", "limit": 25},
        )

        assert proposal["count"] == 1
        assert proposal["entries"][0]["external_user_id"] == "safe-user"
        errors = {str(item.get("error", "")) for item in proposal["invalid_entries"]}
        assert "invalid_json" in errors
        assert "invalid_shape" in errors
        assert "missing_required_fields" in errors
    finally:
        with suppress(Exception):
            await client.call("daemon.shutdown")
        await client.close()
        await asyncio.wait_for(daemon_task, timeout=3)


@pytest.mark.asyncio
async def test_m3_pairing_artifact_parser_rejects_oversized_identifiers(
    model_env: None,
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "data"
    artifact_file = data_dir / "channels" / "pairing_requests.jsonl"
    artifact_file.parent.mkdir(parents=True, exist_ok=True)
    oversized = "u" * (1024 * 1024)
    artifact_file.write_text(
        (
            '{"channel":"discord","external_user_id":"safe-user","workspace_hint":"guild-1"}\n'
            + '{"channel":"discord","external_user_id":"'
            + oversized
            + '","workspace_hint":"guild-1"}\n'
        ),
        encoding="utf-8",
    )

    config = DaemonConfig(
        data_dir=data_dir,
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
        log_level="INFO",
    )
    daemon_task = asyncio.create_task(run_daemon(config))
    client = ControlClient(config.socket_path)
    try:
        await _wait_for_socket(config.socket_path)
        await client.connect()
        proposal = await client.call(
            "channel.pairing_propose",
            {"channel": "discord", "limit": 25},
        )

        assert proposal["count"] == 1
        assert proposal["entries"][0]["external_user_id"] == "safe-user"
        assert any(
            item.get("error") == "missing_required_fields" for item in proposal["invalid_entries"]
        )
    finally:
        with suppress(Exception):
            await client.call("daemon.shutdown")
        await client.close()
        await asyncio.wait_for(daemon_task, timeout=3)


@pytest.mark.asyncio
async def test_m3_pairing_artifact_parser_rejects_json_escaped_control_chars(
    model_env: None,
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "data"
    artifact_file = data_dir / "channels" / "pairing_requests.jsonl"
    artifact_file.parent.mkdir(parents=True, exist_ok=True)
    artifact_file.write_text(
        (
            '{"channel":"discord","external_user_id":"safe-user","workspace_hint":"guild-1"}\n'
            '{"channel":"discord","external_user_id":"null-\\u0000-user","workspace_hint":"guild-1"}\n'
            '{"channel":"disc\\u0001ord","external_user_id":"control-channel","workspace_hint":"guild-1"}\n'
        ),
        encoding="utf-8",
    )

    config = DaemonConfig(
        data_dir=data_dir,
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
        log_level="INFO",
    )
    daemon_task = asyncio.create_task(run_daemon(config))
    client = ControlClient(config.socket_path)
    try:
        await _wait_for_socket(config.socket_path)
        await client.connect()
        proposal = await client.call(
            "channel.pairing_propose",
            {"channel": "discord", "limit": 25},
        )

        assert proposal["count"] == 1
        assert proposal["entries"][0]["external_user_id"] == "safe-user"
        assert any(
            item.get("error") == "missing_required_fields" for item in proposal["invalid_entries"]
        )
    finally:
        with suppress(Exception):
            await client.call("daemon.shutdown")
        await client.close()
        await asyncio.wait_for(daemon_task, timeout=3)
