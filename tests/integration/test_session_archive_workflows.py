"""M2 integration coverage for archive/import and rollback workflows."""

from __future__ import annotations

import asyncio
import json
import textwrap
import zipfile
from contextlib import suppress
from pathlib import Path

import pytest

from shisad.core.api.transport import ControlClient
from shisad.core.config import DaemonConfig
from shisad.core.planner import Planner, PlannerOutput, PlannerResult
from shisad.core.session import Checkpoint, CheckpointStore, Session
from shisad.core.types import SessionId
from shisad.daemon.runner import run_daemon


async def _wait_for_socket(path: Path, timeout: float = 5.0) -> None:
    end = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < end:
        if path.exists():
            return
        await asyncio.sleep(0.01)
    raise TimeoutError(f"Timed out waiting for socket {path}")


@pytest.mark.asyncio
async def test_m2_archive_import_and_rollback_preserve_mode_lockdown_and_binding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SHISAD_MODEL_BASE_URL", "https://api.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_PLANNER_BASE_URL", "https://planner.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_EMBEDDINGS_BASE_URL", "https://embed.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_MONITOR_BASE_URL", "https://monitor.example.com/v1")

    async def _planner(
        self: Planner,
        user_content: str,
        context: object,
        *,
        tools: list[dict[str, object]] | None = None,
        persona_tone_override: str | None = None,
    ) -> PlannerResult:
        _ = (self, user_content, context, tools, persona_tone_override)
        return PlannerResult(
            output=PlannerOutput(assistant_response="archive workflow ok", actions=[]),
            evaluated=[],
            attempts=1,
            provider_response=None,
            messages_sent=(),
        )

    monkeypatch.setattr(Planner, "propose", _planner)

    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        textwrap.dedent(
            """
            version: "1"
            default_require_confirmation: false
            """
        ).strip()
        + "\n"
    )

    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=policy_path,
        log_level="INFO",
    )

    daemon_task = asyncio.create_task(run_daemon(config))
    client = ControlClient(config.socket_path)
    archive_path = tmp_path / "session-archive.shisad-session.zip"

    try:
        await _wait_for_socket(config.socket_path)
        await client.connect()

        created = await client.call(
            "session.create",
            {"channel": "cli", "user_id": "alice", "workspace_id": "ws1"},
        )
        sid = created["session_id"]
        await client.call(
            "session.set_mode",
            {"session_id": sid, "mode": "admin_cleanroom"},
        )
        await client.call(
            "lockdown.set",
            {"session_id": sid, "action": "caution", "reason": "archive-test"},
        )
        await client.call(
            "session.message",
            {
                "session_id": sid,
                "channel": "cli",
                "user_id": "alice",
                "workspace_id": "ws1",
                "content": "hello for archive transcript coverage",
            },
        )

        persisted = json.loads(
            (config.data_dir / "sessions" / "state" / f"{sid}.json").read_text(encoding="utf-8")
        )
        checkpoint = CheckpointStore(config.data_dir / "checkpoints").create(
            Session.model_validate(persisted["session"]),
            state={
                "session": persisted["session"],
                "lockdown": persisted["lockdown"],
                "transcript_entry_count": 2,
            },
        )

        exported = await client.call(
            "session.export",
            {"session_id": sid, "path": str(archive_path)},
        )
        assert exported["exported"] is True
        assert exported["checkpoint_count"] == 1

        imported = await client.call(
            "session.import",
            {"archive_path": str(archive_path)},
        )
        assert imported["imported"] is True
        imported_sid = imported["session_id"]
        assert imported_sid != sid
        assert imported["checkpoint_count"] == 1

        listed = await client.call("session.list", {})
        imported_row = next(row for row in listed["sessions"] if row["id"] == imported_sid)
        assert imported_row["user_id"] == "alice"
        assert imported_row["workspace_id"] == "ws1"
        assert imported_row["mode"] == "admin_cleanroom"
        assert imported_row["lockdown_level"] == "caution"

        transcript_path = config.data_dir / "sessions" / "transcripts" / f"{imported_sid}.jsonl"
        assert transcript_path.exists()
        assert len(transcript_path.read_text(encoding="utf-8").splitlines()) == 2

        await client.call(
            "session.set_mode",
            {"session_id": imported_sid, "mode": "default"},
        )
        await client.call(
            "lockdown.set",
            {"session_id": imported_sid, "action": "resume", "reason": "clear"},
        )

        rolled_back = await client.call(
            "session.rollback",
            {"checkpoint_id": imported["checkpoint_ids"][0]},
        )
        assert rolled_back["rolled_back"] is True

        listed_after = await client.call("session.list", {})
        rolled_back_row = next(row for row in listed_after["sessions"] if row["id"] == imported_sid)
        assert rolled_back_row["mode"] == "admin_cleanroom"
        assert rolled_back_row["lockdown_level"] == "caution"
        assert checkpoint.checkpoint_id != imported["checkpoint_ids"][0]
    finally:
        with suppress(Exception):
            await client.call("daemon.shutdown")
        await client.close()
        await asyncio.wait_for(daemon_task, timeout=3)


@pytest.mark.asyncio
async def test_m2_archive_and_restore_control_paths_fail_closed_with_structured_reasons(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SHISAD_MODEL_BASE_URL", "https://api.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_PLANNER_BASE_URL", "https://planner.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_EMBEDDINGS_BASE_URL", "https://embed.example.com/v1")
    monkeypatch.setenv("SHISAD_MODEL_MONITOR_BASE_URL", "https://monitor.example.com/v1")

    async def _planner(
        self: Planner,
        user_content: str,
        context: object,
        *,
        tools: list[dict[str, object]] | None = None,
        persona_tone_override: str | None = None,
    ) -> PlannerResult:
        _ = (self, user_content, context, tools, persona_tone_override)
        return PlannerResult(
            output=PlannerOutput(assistant_response="archive failure coverage ok", actions=[]),
            evaluated=[],
            attempts=1,
            provider_response=None,
            messages_sent=(),
        )

    monkeypatch.setattr(Planner, "propose", _planner)

    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        textwrap.dedent(
            """
            version: "1"
            default_require_confirmation: false
            """
        ).strip()
        + "\n"
    )

    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=policy_path,
        log_level="INFO",
    )
    daemon_task = asyncio.create_task(run_daemon(config))
    client = ControlClient(config.socket_path)

    try:
        await _wait_for_socket(config.socket_path)
        await client.connect()

        created = await client.call(
            "session.create",
            {"channel": "cli", "user_id": "alice", "workspace_id": "ws1"},
        )
        sid = created["session_id"]

        invalid_archive = tmp_path / "invalid.shisad-session.zip"
        invalid_archive.write_text("not a zip", encoding="utf-8")
        imported = await client.call(
            "session.import",
            {"archive_path": str(invalid_archive)},
        )
        assert imported["imported"] is False
        assert imported["reason"] == "invalid_archive"

        valid_archive = tmp_path / "valid.shisad-session.zip"
        exported_valid = await client.call(
            "session.export",
            {"session_id": sid, "path": str(valid_archive)},
        )
        assert exported_valid["exported"] is True

        original_infolist = zipfile.ZipFile.infolist

        def _encrypted_infolist(self: zipfile.ZipFile) -> list[zipfile.ZipInfo]:
            infos = original_infolist(self)
            for info in infos:
                info.flag_bits |= 0x1
            return infos

        monkeypatch.setattr(
            zipfile.ZipFile,
            "infolist",
            _encrypted_infolist,
        )
        encrypted = await client.call(
            "session.import",
            {"archive_path": str(valid_archive)},
        )
        assert encrypted["imported"] is False
        assert encrypted["reason"] == "encrypted_archive"

        export_destination = tmp_path / "archive-dir"
        export_destination.mkdir()
        exported = await client.call(
            "session.export",
            {"session_id": sid, "path": str(export_destination)},
        )
        assert exported["exported"] is False
        assert exported["reason"] == "archive_write_failed"

        persisted = json.loads(
            (config.data_dir / "sessions" / "state" / f"{sid}.json").read_text(encoding="utf-8")
        )
        checkpoints_dir = config.data_dir / "checkpoints"
        checkpoints_dir.mkdir(parents=True, exist_ok=True)
        unsupported = Checkpoint(
            checkpoint_id="cp-unsupported",
            session_id=SessionId(sid),
            state={"unexpected": "payload"},
        )
        (checkpoints_dir / "cp-unsupported.json").write_text(
            unsupported.model_dump_json(indent=2),
            encoding="utf-8",
        )
        restored = await client.call(
            "session.restore",
            {"checkpoint_id": "cp-unsupported"},
        )
        assert restored["restored"] is False
        assert restored["reason"] == "unsupported_payload_shape"

        invalid_lockdown = Checkpoint(
            checkpoint_id="cp-invalid-lockdown",
            session_id=SessionId(sid),
            state={
                "session": persisted["session"],
                "lockdown": "not-a-dict",
            },
        )
        (checkpoints_dir / "cp-invalid-lockdown.json").write_text(
            invalid_lockdown.model_dump_json(indent=2),
            encoding="utf-8",
        )
        rolled_back = await client.call(
            "session.rollback",
            {"checkpoint_id": "cp-invalid-lockdown"},
        )
        assert rolled_back["rolled_back"] is False
        assert rolled_back["reason"] == "invalid_lockdown_payload"
    finally:
        with suppress(Exception):
            await client.call("daemon.shutdown")
        await client.close()
        await asyncio.wait_for(daemon_task, timeout=3)
