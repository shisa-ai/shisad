"""O4C CLI backup/restore projection tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner
from filelock import FileLock

import shisad.cli.data as data_cli_module
from shisad.cli.main import cli
from shisad.core.data_backup import DataBackupError


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
    assert backup["directory_count"] == 2
    assert backup["permissions"] in {"supported", "unsupported"}
    assert backup["parent_sync"] in {"supported", "unsupported", "failed"}
    assert "backup_id" in backup

    json_restored = tmp_path / "json-restored"
    json_restore_result = runner.invoke(
        cli,
        [
            "data",
            "restore",
            str(archive),
            "--destination",
            str(json_restored),
            "--format",
            "json",
        ],
    )
    assert json_restore_result.exit_code == 0, json_restore_result.output
    json_restore = json.loads(json_restore_result.output)
    assert json_restore["archive"] == str(archive)
    assert json_restore["destination"] == str(json_restored)
    assert json_restore["directory_count"] == 2
    assert json_restore["offline_health_verified"] is False
    assert json_restore["sensitive_archive"] is True
    assert json_restore["sensitive_archive_handling"] == "retain in operator-controlled storage"
    assert "SHISAD_MEMORY_MASTER_KEY" in json_restore["cross_root_encrypted_memory"]
    assert "original absolute data root" in json_restore["cross_root_encrypted_memory"]

    human_archive = tmp_path / "human-snapshot.shisad-backup"
    backup_result = runner.invoke(cli, ["data", "backup", str(human_archive)])
    assert backup_result.exit_code == 0, backup_result.output
    assert str(source) in backup_result.output
    assert str(human_archive) in backup_result.output
    assert "2 directories" in backup_result.output
    assert "shisad data restore" in backup_result.output
    assert "permissions=" in backup_result.output
    assert "Sensitive archive" in backup_result.output

    restore_result = runner.invoke(
        cli,
        [
            "data",
            "restore",
            str(human_archive),
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
    assert str(human_archive) in restore_result.output
    assert str(restored) in restore_result.output
    assert "2 directories" in restore_result.output
    assert "permissions=" in restore_result.output
    assert "Sensitive archive" in restore_result.output
    assert "SHISAD_MEMORY_MASTER_KEY" in restore_result.output
    assert "original absolute data root" in restore_result.output
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


def test_drh1_backup_residue_refusal_uses_the_existing_json_error_envelope(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "data"
    source.mkdir()
    monkeypatch.setenv("SHISAD_DATA_DIR", str(source))

    def refuse_with_residue(_source: Path, _destination: Path) -> object:
        raise DataBackupError("temporary backup residue retained at an operator path")

    monkeypatch.setattr(data_cli_module, "create_data_backup", refuse_with_residue)

    result = CliRunner().invoke(
        cli,
        ["data", "backup", str(tmp_path / "snapshot.shisad-backup"), "--format", "json"],
    )

    assert result.exit_code == 3
    payload = json.loads(result.output)
    assert payload["error_type"] == "data_backup"
    assert "residue retained" in payload["technical_details"]
    assert "Traceback" not in result.output
