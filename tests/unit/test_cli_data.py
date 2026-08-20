"""O4C CLI backup/restore projection tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner
from filelock import FileLock

from shisad.cli.main import cli


def test_o4c_data_backup_restore_json_and_human_guidance(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "data"
    state = source / "sessions" / "state" / "session.json"
    state.parent.mkdir(parents=True)
    state.write_text('{"durable":true}\n', encoding="utf-8")
    monkeypatch.setenv("SHISAD_DATA_DIR", str(source))
    archive = tmp_path / "snapshot.shisad-backup"
    restored = tmp_path / "restored"
    runner = CliRunner()

    backup_result = runner.invoke(
        cli,
        ["data", "backup", str(archive), "--format", "json"],
    )
    assert backup_result.exit_code == 0, backup_result.output
    backup = json.loads(backup_result.output)
    assert backup["verified"] is True
    assert backup["source"] == str(source)
    assert backup["destination"] == str(archive)
    assert backup["sensitive_archive"] is True
    assert backup["file_count"] == 1
    assert "backup_id" in backup

    restore_result = runner.invoke(
        cli,
        [
            "data",
            "restore",
            str(archive),
            "--destination",
            str(restored),
        ],
    )
    assert restore_result.exit_code == 0, restore_result.output
    assert "Verified backup" in restore_result.output
    assert "shisad start" in restore_result.output
    assert "shisad status" in restore_result.output
    assert "shisad doctor" in restore_result.output
    assert "offline health is not yet verified" in restore_result.output.lower()
    assert (restored / "sessions" / "state" / "session.json").read_bytes() == state.read_bytes()


def test_o4c_data_backup_lock_failure_is_structured_and_nonmutating(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "data"
    source.mkdir()
    (source / "pending_actions.json").write_text("[]\n", encoding="utf-8")
    monkeypatch.setenv("SHISAD_DATA_DIR", str(source))
    archive = tmp_path / "snapshot.shisad-backup"
    lock = FileLock(str(source / ".shisad.lock"), timeout=0)

    with lock:
        result = CliRunner().invoke(
            cli,
            ["data", "backup", str(archive), "--format", "json"],
        )

    assert result.exit_code == 3
    payload = json.loads(result.output)
    assert payload["error_type"] == "data_backup"
    assert payload["exit_code"] == 3
    assert "stop" in payload["next_action"].lower()
    assert not archive.exists()
