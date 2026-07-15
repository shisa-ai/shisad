"""F3 owner-only state and control-artifact postconditions."""

from __future__ import annotations

import os
import stat
from pathlib import Path
from types import SimpleNamespace

import shisad.daemon.handlers._impl_session as session_impl
from shisad.core.atomic_state import durable_append_bytes
from shisad.core.audit import AuditLog
from shisad.security.control_plane.engine import ControlPlaneEngine
from shisad.security.control_plane.schema import Origin, build_action
from shisad.ui.dashboard import SecurityDashboard


def test_auxiliary_state_artifacts_are_owner_only_under_permissive_umask(
    tmp_path: Path,
) -> None:
    pairing_path = tmp_path / "data" / "channels" / "pairing_requests.jsonl"
    marks_path = tmp_path / "data" / "dashboard" / "false_positives.json"
    task_impl = object.__new__(session_impl.SessionImplMixin)
    task_impl._config = SimpleNamespace(data_dir=tmp_path / "data")

    previous_umask = os.umask(0)
    try:
        durable_append_bytes(pairing_path, b'{"channel":"discord","id":"one"}\n')
        dashboard = SecurityDashboard(
            audit_log=AuditLog(tmp_path / "audit.jsonl"),
            marks_path=marks_path,
        )
        dashboard.mark_false_positive(event_id="evt-1", reason="reviewed")
        task_path = Path(
            task_impl._write_task_artifact(
                task_session_id=session_impl.SessionId("task-owner-only"),
                filename="self_check.json",
                payload={"status": "complete"},
            )
        )
    finally:
        os.umask(previous_umask)

    for path in (pairing_path, marks_path, task_path):
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700


def test_control_plane_state_artifacts_are_owner_only_under_permissive_umask(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "data"
    origin = Origin(
        session_id="owner-only-control-plane",
        user_id="alice",
        workspace_id="workspace",
        actor="test",
    )

    previous_umask = os.umask(0)
    try:
        engine = ControlPlaneEngine.build(data_dir=data_dir, workspace_roots=[tmp_path])
        engine.begin_precontent_plan(
            session_id=origin.session_id,
            goal=f"read {tmp_path / 'source.txt'}",
            origin=origin,
            ttl_seconds=300,
            max_actions=5,
        )
        action = build_action(
            tool_name="file.read",
            arguments={"path": str(tmp_path / "source.txt")},
            origin=origin,
            workspace_roots=[tmp_path],
        )
        engine.observe_denied_action(
            action=action,
            source="permission_test",
            reason_code="pep:test",
        )
        engine.observe_runtime_network(
            origin=origin,
            tool_name="http.request",
            destination_host="api.example.com",
            destination_port=443,
            protocol="https",
            allowed=True,
            reason="confirmed",
            request_size=128,
            resolved_addresses=["203.0.113.10"],
        )
    finally:
        os.umask(previous_umask)

    control_plane_dir = data_dir / "control_plane"
    assert stat.S_IMODE(control_plane_dir.stat().st_mode) == 0o700
    for name in ("history.jsonl", "plans.json", "network_baseline.json", "audit.jsonl"):
        path = control_plane_dir / name
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
