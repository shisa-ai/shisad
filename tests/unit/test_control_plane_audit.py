"""M6 coverage tests for control-plane audit log edge paths."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from shisad.core.atomic_state import (
    DurableAppendError,
    DurableAppendStage,
    StateLoadStatus,
    StatePersistenceDegradedError,
)
from shisad.security.control_plane.audit import ControlPlaneAuditLog


def test_m6_control_plane_audit_missing_file_verify_is_ok(tmp_path: Path) -> None:
    path = tmp_path / "control-plane-audit.jsonl"
    log = ControlPlaneAuditLog(path)
    assert log.path == path
    assert log.entry_count == 0
    assert log.verify_chain() == (True, 0, "")


def test_m6_control_plane_audit_resume_and_query_filters(tmp_path: Path) -> None:
    path = tmp_path / "control-plane-audit.jsonl"
    first = ControlPlaneAuditLog(path)
    first.append(
        event_type="ControlPlaneActionObserved",
        session_id="s-1",
        actor="planner",
        data={"kind": "fs_read"},
    )
    first.append(
        event_type="ControlPlaneNetworkObserved",
        session_id="s-2",
        actor="planner",
        data={"host": "api.good.com"},
    )

    resumed = ControlPlaneAuditLog(path)
    assert resumed.entry_count == 2
    assert resumed.verify_chain()[0] is True

    event_rows = resumed.query(event_type="ControlPlaneNetworkObserved")
    assert len(event_rows) == 1
    assert event_rows[0]["event_type"] == "ControlPlaneNetworkObserved"

    session_rows = resumed.query(session_id="s-1")
    assert len(session_rows) == 1
    assert session_rows[0]["session_id"] == "s-1"


def test_m6_control_plane_audit_verify_chain_invalid_entry(tmp_path: Path) -> None:
    path = tmp_path / "control-plane-audit.jsonl"
    log = ControlPlaneAuditLog(path)
    log.append(event_type="ControlPlaneActionObserved", session_id="s-1", actor="planner", data={})
    with path.open("a", encoding="utf-8") as handle:
        handle.write("{not-json}\n")

    ok, _, error = log.verify_chain()
    assert ok is False
    assert "invalid entry" in error

    resumed = ControlPlaneAuditLog(path)
    assert resumed.state_load_result.status == StateLoadStatus.CORRUPT
    assert resumed.entry_count == 0
    assert resumed.query() == []


def test_m6_control_plane_audit_verify_chain_detects_data_hash_mismatch(tmp_path: Path) -> None:
    path = tmp_path / "control-plane-audit.jsonl"
    log = ControlPlaneAuditLog(path)
    log.append(
        event_type="ControlPlaneActionObserved",
        session_id="s-1",
        actor="planner",
        data={"k": "v"},
    )

    entry = json.loads(path.read_text(encoding="utf-8").splitlines()[0])
    entry["data_hash"] = "broken"
    path.write_text(json.dumps(entry) + "\n", encoding="utf-8")

    ok, _, error = log.verify_chain()
    assert ok is False
    assert "data hash mismatch" in error


def test_f3_control_plane_audit_corruption_is_retained_and_blocks_append(
    tmp_path: Path,
) -> None:
    path = tmp_path / "control-plane-audit.jsonl"
    corrupt_bytes = b'{"event_type":"torn"'
    path.write_bytes(corrupt_bytes)

    log = ControlPlaneAuditLog(path)

    assert log.state_load_result.status == StateLoadStatus.CORRUPT
    assert log.entry_count == 0
    with pytest.raises(StatePersistenceDegradedError, match="control_plane_audit"):
        log.append(event_type="new", session_id="s", actor="a", data={})
    assert path.read_bytes() == corrupt_bytes


def test_f3_control_plane_audit_commit_uncertainty_keeps_chain_state(
    tmp_path: Path,
) -> None:
    path = tmp_path / "control-plane-audit.jsonl"
    log = ControlPlaneAuditLog(path)

    def _inject(stage: DurableAppendStage) -> None:
        if stage == DurableAppendStage.FILE_FSYNC:
            raise OSError("fault:file_fsync")

    log._state_fault_injector = _inject
    with pytest.raises(DurableAppendError):
        log.append(event_type="uncertain", session_id="s", actor="a", data={})

    assert log.entry_count == 0
    assert log.state_status()["stage"] == "file_fsync"
    with pytest.raises(StatePersistenceDegradedError):
        log.append(event_type="retry", session_id="s", actor="a", data={})


def test_f3_control_plane_audit_rejects_same_path_replacement_before_append(
    tmp_path: Path,
) -> None:
    path = tmp_path / "control-plane-audit.jsonl"
    log = ControlPlaneAuditLog(path)
    log.append(event_type="retained", session_id="s", actor="a", data={"id": 1})
    replacement = tmp_path / "replacement-control-plane-audit.jsonl"
    replacement.write_bytes(b"")
    replacement.chmod(0o600)
    replacement.replace(path)

    with pytest.raises(DurableAppendError):
        log.append(event_type="blocked", session_id="s", actor="a", data={"id": 2})

    assert log.state_degraded is True
    assert path.read_bytes() == b""
