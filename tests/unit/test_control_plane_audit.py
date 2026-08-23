"""M6 coverage tests for control-plane audit log edge paths."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from shisad.core.audit_segments import AuditIntegrityError, AuditUnavailableError
from shisad.core.types import Capability
from shisad.security.control_plane.audit import ControlPlaneAuditLog
from shisad.security.control_plane.engine import ControlPlaneEngine
from shisad.security.control_plane.schema import Origin


def test_o4d_unavailable_audit_rejects_control_plane_before_state_change(
    tmp_path: Path,
) -> None:
    engine = ControlPlaneEngine.build(data_dir=tmp_path / "cp-o4d-unavailable")
    origin = Origin(
        session_id="s-o4d-unavailable",
        user_id="user-1",
        workspace_id="ws-1",
        actor="planner",
        trust_level="untrusted",
    )
    engine.audit._segments.mark_unavailable("audit.append_failed")

    with pytest.raises(AuditUnavailableError, match=r"audit\.append_failed"):
        engine.begin_precontent_plan(
            session_id=origin.session_id,
            goal="read a file",
            origin=origin,
            ttl_seconds=300,
            max_actions=2,
            capabilities={Capability.FILE_READ},
        )

    assert engine.active_plan_hash(origin.session_id) == ""


def test_o4d_first_completion_failure_retains_write_ahead_intent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = ControlPlaneEngine.build(data_dir=tmp_path / "cp-o4d-first-failure")
    origin = Origin(
        session_id="s-o4d-first-failure",
        user_id="user-1",
        workspace_id="ws-1",
        actor="planner",
        trust_level="untrusted",
    )
    real_append = engine.audit.append

    def fail_after_intent(**kwargs: object) -> None:
        if kwargs.get("event_type") == "plan_committed":
            raise OSError("completion write failed")
        real_append(**kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(engine.audit, "append", fail_after_intent)
    with pytest.raises(OSError, match="completion write failed"):
        engine.begin_precontent_plan(
            session_id=origin.session_id,
            goal="read a file",
            origin=origin,
            ttl_seconds=300,
            max_actions=2,
            capabilities={Capability.FILE_READ},
        )

    assert engine.active_plan_hash(origin.session_id)
    rows = engine.audit.query(session_id=origin.session_id)
    assert [row["event_type"] for row in rows] == ["plan_commit_requested"]


def test_o4d_reserved_execution_status_returns_live_audit_lifecycle(tmp_path: Path) -> None:
    engine = ControlPlaneEngine.build(data_dir=tmp_path / "cp-o4d-live-status")
    engine.audit._segments.mark_unavailable("audit.append_failed")

    payload = json.loads(engine.execution_status(idempotency_key="\x00shisad.audit.lifecycle.v1"))

    assert payload["state"] == "unavailable"
    assert payload["reason_code"] == "audit.append_failed"
    assert payload["verified"] is False


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

    entry = next(
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if json.loads(line).get("record_type") != "shisad.audit.segment"
    )
    entry["data_hash"] = "broken"
    lines = path.read_text(encoding="utf-8").splitlines()
    entry_index = next(
        index
        for index, line in enumerate(lines)
        if json.loads(line).get("record_type") != "shisad.audit.segment"
    )
    lines[entry_index] = json.dumps(entry)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    ok, _, error = log.verify_chain()
    assert ok is False
    assert "data hash mismatch" in error


def test_o4d_control_plane_refuses_corrupt_chain_at_admission(tmp_path: Path) -> None:
    path = tmp_path / "control-plane-audit.jsonl"
    log = ControlPlaneAuditLog(path)
    log.append(
        event_type="ControlPlaneActionObserved",
        session_id="s-1",
        actor="planner",
        data={"kind": "fs_read"},
    )
    lines = path.read_text(encoding="utf-8").splitlines()
    entry_index = next(
        index
        for index, line in enumerate(lines)
        if json.loads(line).get("record_type") != "shisad.audit.segment"
    )
    row = json.loads(lines[entry_index])
    row["data_hash"] = "tampered"
    lines[entry_index] = json.dumps(row)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    with pytest.raises(AuditIntegrityError, match="data hash mismatch"):
        ControlPlaneAuditLog(path)


def test_o4d_control_plane_append_failure_latches_decisions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "control-plane-audit.jsonl"
    log = ControlPlaneAuditLog(path)

    def fail_append(_payload: str, _terminal_hash: str) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(log._segments, "append", fail_append)
    with pytest.raises(OSError):
        log.append(
            event_type="ControlPlaneActionObserved",
            session_id="s-1",
            actor="planner",
            data={},
        )
    assert log.lifecycle_status["state"] == "unavailable"
    assert log.lifecycle_status["reason_code"] == "audit.append_failed"

    with pytest.raises(AuditUnavailableError, match=r"audit\.append_failed"):
        log.append(
            event_type="ControlPlaneActionObserved",
            session_id="s-2",
            actor="planner",
            data={},
        )
