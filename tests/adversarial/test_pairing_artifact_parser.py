"""Adversarial parser coverage for channel pairing request artifacts."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
from contextlib import suppress
from pathlib import Path

import pytest

from shisad.core.api.transport import ControlClient, JsonRpcCallError
from shisad.core.config import DaemonConfig
from shisad.daemon.runner import run_daemon
from tests.helpers.daemon import wait_for_socket as _wait_for_socket


@pytest.fixture
def model_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SHISAD_MODEL_BASE_URL", "https://api.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_PLANNER_BASE_URL", "https://planner.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_EMBEDDINGS_BASE_URL", "https://embed.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_MONITOR_BASE_URL", "https://monitor.example.com/v1")


def _artifact_dir(data_dir: Path, workspace_hint: str) -> Path:
    workspace_scope = hashlib.sha256(workspace_hint.encode("utf-8")).hexdigest()
    return data_dir / "channels" / "pairing_requests" / f"uid-{os.getuid()}" / workspace_scope


def _valid_row(
    *,
    external_user_id: str = "safe-user",
    workspace_hint: str = "guild-1",
    owner_uid: int | None = None,
) -> dict[str, object]:
    return {
        "schema": 1,
        "owner_uid": os.getuid() if owner_uid is None else owner_uid,
        "channel": "discord",
        "workspace_hint": workspace_hint,
        "external_user_id": external_user_id,
        "reason": "identity_not_allowlisted",
        "requested_at": "2026-07-22T00:00:00+00:00",
    }


def _assert_no_pairing_proposal(data_dir: Path) -> None:
    proposal_root = data_dir / "proposals" / "channel_pairing"
    assert not proposal_root.exists() or not any(proposal_root.rglob("*.json"))


@pytest.mark.asyncio
async def test_f7c_pairing_artifact_parser_rejects_entire_malformed_artifact(
    model_env: None,
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "data"
    artifact_file = _artifact_dir(data_dir, "guild-1") / "fixture.jsonl"
    artifact_file.parent.mkdir(parents=True, exist_ok=True)
    valid = json.dumps(_valid_row(), sort_keys=True).encode("utf-8")
    artifact_file.write_bytes(
        valid
        + b"\n"
        + b'{"schema":1,"owner_uid":0,"channel":"discord",'
        + b'"external_user_id":"truncated"'
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
        with pytest.raises(JsonRpcCallError, match="pairing_request_artifact_corrupt"):
            await client.call(
                "channel.pairing_propose",
                {"channel": "discord", "workspace_hint": "guild-1", "limit": 25},
            )
        _assert_no_pairing_proposal(data_dir)
    finally:
        with suppress(Exception):
            await client.call("daemon.shutdown")
        await client.close()
        await asyncio.wait_for(daemon_task, timeout=5)


@pytest.mark.asyncio
async def test_f7c_pairing_artifact_parser_rejects_oversized_identifiers_without_partial_output(
    model_env: None,
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "data"
    artifact_file = _artifact_dir(data_dir, "guild-1") / "fixture.jsonl"
    artifact_file.parent.mkdir(parents=True, exist_ok=True)
    oversized = "u" * (1024 * 1024)
    rows = [_valid_row(), _valid_row(external_user_id=oversized)]
    artifact_file.write_text("".join(f"{json.dumps(row)}\n" for row in rows), encoding="utf-8")

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
        with pytest.raises(JsonRpcCallError, match="pairing_request_artifact_corrupt"):
            await client.call(
                "channel.pairing_propose",
                {"channel": "discord", "workspace_hint": "guild-1", "limit": 25},
            )
        _assert_no_pairing_proposal(data_dir)
    finally:
        with suppress(Exception):
            await client.call("daemon.shutdown")
        await client.close()
        await asyncio.wait_for(daemon_task, timeout=5)


@pytest.mark.asyncio
async def test_f7c_pairing_artifact_parser_rejects_json_escaped_control_chars(
    model_env: None,
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "data"
    artifact_file = _artifact_dir(data_dir, "guild-1") / "fixture.jsonl"
    artifact_file.parent.mkdir(parents=True, exist_ok=True)
    row = _valid_row(external_user_id="null-user")
    encoded = json.dumps(row).replace("null-user", "null-\\u0000-user")
    artifact_file.write_text(
        f"{json.dumps(_valid_row())}\n{encoded}\n",
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
        with pytest.raises(JsonRpcCallError, match="pairing_request_artifact_corrupt"):
            await client.call(
                "channel.pairing_propose",
                {"channel": "discord", "workspace_hint": "guild-1", "limit": 25},
            )
        _assert_no_pairing_proposal(data_dir)
    finally:
        with suppress(Exception):
            await client.call("daemon.shutdown")
        await client.close()
        await asyncio.wait_for(daemon_task, timeout=5)


@pytest.mark.asyncio
async def test_f7c_pairing_artifact_parser_rejects_duplicate_members(
    model_env: None,
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "data"
    artifact_file = _artifact_dir(data_dir, "guild-1") / "fixture.jsonl"
    artifact_file.parent.mkdir(parents=True, exist_ok=True)
    valid = json.dumps(_valid_row(), sort_keys=True)
    duplicate = valid.replace('"schema": 1', '"schema": 1, "schema": 1', 1)
    artifact_file.write_text(f"{duplicate}\n", encoding="utf-8")

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
        with pytest.raises(JsonRpcCallError, match="pairing_request_artifact_corrupt"):
            await client.call(
                "channel.pairing_propose",
                {"workspace_hint": "guild-1", "limit": 25},
            )
        _assert_no_pairing_proposal(data_dir)
    finally:
        with suppress(Exception):
            await client.call("daemon.shutdown")
        await client.close()
        await asyncio.wait_for(daemon_task, timeout=5)


@pytest.mark.parametrize(
    ("case", "payload"),
    [
        ("invalid-utf8", b"\xff\n"),
        (
            "wrong-owner",
            json.dumps(_valid_row(owner_uid=os.getuid() + 1), sort_keys=True).encode("utf-8")
            + b"\n",
        ),
        (
            "wrong-workspace",
            json.dumps(_valid_row(workspace_hint="guild-2"), sort_keys=True).encode("utf-8")
            + b"\n",
        ),
    ],
)
@pytest.mark.asyncio
async def test_f7c_pairing_artifact_parser_rejects_invalid_encoding_or_scope(
    model_env: None,
    tmp_path: Path,
    case: str,
    payload: bytes,
) -> None:
    data_dir = tmp_path / "data"
    artifact_file = _artifact_dir(data_dir, "guild-1") / f"{case}.jsonl"
    artifact_file.parent.mkdir(parents=True, exist_ok=True)
    artifact_file.write_bytes(payload)

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
        with pytest.raises(JsonRpcCallError, match="pairing_request_artifact_corrupt"):
            await client.call(
                "channel.pairing_propose",
                {"workspace_hint": "guild-1", "limit": 25},
            )
        _assert_no_pairing_proposal(data_dir)
        assert artifact_file.read_bytes() == payload
    finally:
        with suppress(Exception):
            await client.call("daemon.shutdown")
        await client.close()
        await asyncio.wait_for(daemon_task, timeout=5)


@pytest.mark.asyncio
async def test_f7c_pairing_artifact_parser_rejects_unsafe_symlink_path(
    model_env: None,
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "data"
    artifact_dir = _artifact_dir(data_dir, "guild-1")
    artifact_dir.mkdir(parents=True, exist_ok=True)
    outside = tmp_path / "outside.jsonl"
    outside.write_text(f"{json.dumps(_valid_row())}\n", encoding="utf-8")
    (artifact_dir / "linked.jsonl").symlink_to(outside)

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
        with pytest.raises(JsonRpcCallError, match="pairing_request_artifact_corrupt"):
            await client.call(
                "channel.pairing_propose",
                {"workspace_hint": "guild-1", "limit": 25},
            )
        _assert_no_pairing_proposal(data_dir)
    finally:
        with suppress(Exception):
            await client.call("daemon.shutdown")
        await client.close()
        await asyncio.wait_for(daemon_task, timeout=5)
