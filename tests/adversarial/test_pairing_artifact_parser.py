"""Adversarial parser coverage for channel pairing request artifacts."""

from __future__ import annotations

import asyncio
import json
import stat
from contextlib import suppress
from pathlib import Path

import pytest

import shisad.daemon.handlers._impl as impl_module
from shisad.core.api.transport import ControlClient
from shisad.core.atomic_state import DurableAppendError, DurableAppendStage
from shisad.core.config import DaemonConfig
from shisad.daemon.runner import run_daemon
from tests.helpers.daemon import wait_for_socket as _wait_for_socket


@pytest.fixture
def model_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SHISAD_MODEL_BASE_URL", "https://api.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_PLANNER_BASE_URL", "https://planner.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_EMBEDDINGS_BASE_URL", "https://embed.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_MONITOR_BASE_URL", "https://monitor.example.com/v1")


def _owner_only_pairing_artifact_path(data_dir: Path) -> Path:
    data_dir.mkdir(mode=0o700)
    artifact_dir = data_dir / "channels"
    artifact_dir.mkdir(mode=0o700)
    return artifact_dir / "pairing_requests.jsonl"


@pytest.mark.asyncio
async def test_m3_pairing_artifact_parser_skips_control_chars_and_malformed_lines(
    model_env: None,
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "data"
    artifact_file = _owner_only_pairing_artifact_path(data_dir)
    artifact_file.write_bytes(
        b'{"channel":"discord","external_user_id":"safe-user","workspace_hint":"guild-1"}\n'
        b'{"channel":"discord","external_user_id":"null-\x00-user","workspace_hint":"guild-1"}\n'
        b'{"channel":"discord","external_user_id":"line\nbreak","workspace_hint":"guild-1"}\n'
        b'{"channel":"discord","external_user_id":"truncated"\n'
        b'["not","a","mapping"]\n'
        b'{"channel":"discord"}\n'
    )
    artifact_file.chmod(0o600)

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
        proposal_path = Path(str(proposal["proposal_path"]))
        proposal_payload = json.loads(proposal_path.read_text(encoding="utf-8"))
        assert proposal_payload["proposal_id"] == proposal["proposal_id"]
        assert stat.S_IMODE(proposal_path.parent.stat().st_mode) == 0o700
        assert stat.S_IMODE(proposal_path.stat().st_mode) == 0o600
    finally:
        with suppress(Exception):
            await client.call("daemon.shutdown")
        await client.close()
        await asyncio.wait_for(daemon_task, timeout=5)


@pytest.mark.asyncio
async def test_m3_pairing_artifact_parser_rejects_oversized_identifiers(
    model_env: None,
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "data"
    artifact_file = _owner_only_pairing_artifact_path(data_dir)
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
    artifact_file.chmod(0o600)

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
        await asyncio.wait_for(daemon_task, timeout=5)


@pytest.mark.asyncio
async def test_m3_pairing_artifact_parser_rejects_json_escaped_control_chars(
    model_env: None,
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "data"
    artifact_file = _owner_only_pairing_artifact_path(data_dir)
    artifact_file.write_text(
        (
            '{"channel":"discord","external_user_id":"safe-user","workspace_hint":"guild-1"}\n'
            '{"channel":"discord","external_user_id":"null-\\u0000-user","workspace_hint":"guild-1"}\n'
            '{"channel":"disc\\u0001ord","external_user_id":"control-channel","workspace_hint":"guild-1"}\n'
        ),
        encoding="utf-8",
    )
    artifact_file.chmod(0o600)

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
        await asyncio.wait_for(daemon_task, timeout=5)


@pytest.mark.asyncio
@pytest.mark.parametrize("invalid_kind", ["symlink", "hardlink", "swap"])
async def test_f3_pairing_proposal_rejects_replaced_artifact_authority(
    model_env: None,
    tmp_path: Path,
    invalid_kind: str,
) -> None:
    data_dir = tmp_path / "data"
    artifact_file = _owner_only_pairing_artifact_path(data_dir)
    artifact_file.write_text(
        '{"channel":"discord","external_user_id":"original-user"}\n',
        encoding="utf-8",
    )
    artifact_file.chmod(0o600)
    config = DaemonConfig(
        data_dir=data_dir,
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
        log_level="INFO",
    )
    daemon_task = asyncio.create_task(run_daemon(config))
    client = ControlClient(config.socket_path)
    crafted = tmp_path / "crafted-pairing-requests.jsonl"
    crafted_bytes = b'{"channel":"discord","external_user_id":"crafted-user"}\n'
    crafted.write_bytes(crafted_bytes)
    crafted.chmod(0o600)
    try:
        await _wait_for_socket(config.socket_path)
        await client.connect()
        artifact_file.unlink()
        if invalid_kind == "symlink":
            artifact_file.symlink_to(crafted)
        elif invalid_kind == "hardlink":
            artifact_file.hardlink_to(crafted)
        else:
            crafted.replace(artifact_file)

        with pytest.raises(RuntimeError, match="State authority unavailable"):
            await client.call(
                "channel.pairing_propose",
                {"channel": "discord", "limit": 25},
            )

        doctor = await client.call("doctor.check", {"component": "channels"})
        pairing_status = doctor["checks"]["channels"]["pairing_requests"]
        assert pairing_status["status"] == "degraded"
        assert pairing_status["stage"] == "proposal_read"
        assert pairing_status["fail_closed"] is True
        assert not (data_dir / "proposals" / "channel_pairing").exists()
        if invalid_kind != "swap":
            assert crafted.read_bytes() == crafted_bytes
        else:
            assert artifact_file.read_bytes() == crafted_bytes
    finally:
        with suppress(Exception):
            await client.call("daemon.shutdown")
        await client.close()
        await asyncio.wait_for(daemon_task, timeout=5)


@pytest.mark.asyncio
async def test_f3_pairing_request_append_rejects_symlink_target(
    model_env: None,
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "data"
    artifact_file = _owner_only_pairing_artifact_path(data_dir)
    outside = tmp_path / "outside.jsonl"
    outside.write_text("outside\n", encoding="utf-8")
    artifact_file.symlink_to(outside)
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
        with pytest.raises(RuntimeError, match="State authority unavailable"):
            await client.call(
                "channel.ingest",
                {
                    "message": {
                        "channel": "discord",
                        "external_user_id": "unpaired-user",
                        "workspace_hint": "guild-1",
                        "content": "hello",
                        "message_id": "m-symlink",
                        "reply_target": "chan-1",
                    }
                },
            )
        assert outside.read_text(encoding="utf-8") == "outside\n"
    finally:
        with suppress(Exception):
            await client.call("daemon.shutdown")
        await client.close()
        await asyncio.wait_for(daemon_task, timeout=5)


@pytest.mark.asyncio
async def test_f3_pairing_append_failure_allows_same_process_retry(
    model_env: None,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data_dir = tmp_path / "data"
    artifact_file = data_dir / "channels" / "pairing_requests.jsonl"
    config = DaemonConfig(
        data_dir=data_dir,
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
        log_level="INFO",
    )
    real_append = impl_module.durable_append_bytes
    attempts = 0

    def _fail_first_append(path: Path, payload: bytes) -> None:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise DurableAppendError(
                path=path,
                stage=DurableAppendStage.FILE_OPEN,
                publication_may_have_committed=False,
            )
        real_append(path, payload)

    monkeypatch.setattr(impl_module, "durable_append_bytes", _fail_first_append)
    daemon_task = asyncio.create_task(run_daemon(config))
    client = ControlClient(config.socket_path)
    message = {
        "channel": "discord",
        "external_user_id": "retry-user",
        "workspace_hint": "guild-1",
        "content": "hello",
        "reply_target": "chan-1",
    }
    try:
        await _wait_for_socket(config.socket_path)
        await client.connect()
        with pytest.raises(RuntimeError, match="Internal error"):
            await client.call(
                "channel.ingest",
                {"message": {**message, "message_id": "m-first"}},
            )
        assert not artifact_file.exists()

        retry = await client.call(
            "channel.ingest",
            {"message": {**message, "message_id": "m-retry"}},
        )

        assert "Pairing request recorded" in retry["response"]
        rows = artifact_file.read_text(encoding="utf-8").splitlines()
        assert len(rows) == 1
        assert json.loads(rows[0])["external_user_id"] == "retry-user"
        assert attempts == 2
    finally:
        with suppress(Exception):
            await client.call("daemon.shutdown")
        await client.close()
        await asyncio.wait_for(daemon_task, timeout=5)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "fault_stage",
    [DurableAppendStage.FILE_FSYNC, DurableAppendStage.PARENT_FSYNC],
)
async def test_f3_pairing_commit_uncertainty_fails_closed_without_retry(
    model_env: None,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fault_stage: DurableAppendStage,
) -> None:
    data_dir = tmp_path / "data"
    artifact_file = data_dir / "channels" / "pairing_requests.jsonl"
    config = DaemonConfig(
        data_dir=data_dir,
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
        log_level="INFO",
    )
    real_append = impl_module.durable_append_bytes
    attempts = 0

    def _uncertain_append(path: Path, payload: bytes) -> None:
        nonlocal attempts
        attempts += 1

        def _inject(stage: DurableAppendStage) -> None:
            if stage == fault_stage:
                raise OSError(f"fault:{stage.value}")

        real_append(path, payload, fault_injector=_inject)

    monkeypatch.setattr(impl_module, "durable_append_bytes", _uncertain_append)
    daemon_task = asyncio.create_task(run_daemon(config))
    client = ControlClient(config.socket_path)
    message = {
        "channel": "discord",
        "external_user_id": "uncertain-user",
        "workspace_hint": "guild-1",
        "content": "hello",
        "reply_target": "chan-1",
    }
    try:
        await _wait_for_socket(config.socket_path)
        await client.connect()
        with pytest.raises(RuntimeError, match="Internal error"):
            await client.call(
                "channel.ingest",
                {"message": {**message, "message_id": "m-first"}},
            )
        uncertain_bytes = artifact_file.read_bytes()
        assert uncertain_bytes.endswith(b"\n")

        with pytest.raises(RuntimeError, match="State authority unavailable"):
            await client.call(
                "channel.ingest",
                {"message": {**message, "message_id": "m-retry"}},
            )

        doctor = await client.call("doctor.check", {"component": "channels"})
        status = await client.call("daemon.status")
        pairing_status = doctor["checks"]["channels"]["pairing_requests"]
        assert doctor["status"] == "degraded"
        assert pairing_status["status"] == "degraded"
        assert pairing_status["stage"] == fault_stage.value
        assert pairing_status["fail_closed"] is True
        assert status["pairing_requests"] == pairing_status
        assert "pairing_requests" not in status["channels"]
        assert artifact_file.read_bytes() == uncertain_bytes
        assert attempts == 1
    finally:
        with suppress(Exception):
            await client.call("daemon.shutdown")
        await client.close()
        await asyncio.wait_for(daemon_task, timeout=5)


@pytest.mark.asyncio
async def test_f3_pairing_unterminated_startup_artifact_fails_closed(
    model_env: None,
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "data"
    artifact_file = _owner_only_pairing_artifact_path(data_dir)
    partial_bytes = b'{"channel":"discord"'
    artifact_file.write_bytes(partial_bytes)
    artifact_file.chmod(0o600)
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
        doctor = await client.call("doctor.check", {"component": "channels"})
        pairing_status = doctor["checks"]["channels"]["pairing_requests"]
        assert doctor["status"] == "degraded"
        assert pairing_status["reason"] == "artifact_unterminated_row"

        with pytest.raises(RuntimeError, match="State authority unavailable"):
            await client.call(
                "channel.ingest",
                {
                    "message": {
                        "channel": "discord",
                        "external_user_id": "blocked-user",
                        "workspace_hint": "guild-1",
                        "content": "hello",
                        "message_id": "m-partial",
                        "reply_target": "chan-1",
                    }
                },
            )
        assert artifact_file.read_bytes() == partial_bytes
    finally:
        with suppress(Exception):
            await client.call("daemon.shutdown")
        await client.close()
        await asyncio.wait_for(daemon_task, timeout=5)
