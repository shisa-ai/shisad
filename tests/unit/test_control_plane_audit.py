"""M6 coverage tests for control-plane audit log edge paths."""

from __future__ import annotations

import json
from pathlib import Path

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
