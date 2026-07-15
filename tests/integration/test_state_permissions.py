"""F3 owner-only state and control-artifact postconditions."""

from __future__ import annotations

import os
import stat
from pathlib import Path
from types import SimpleNamespace

import shisad.daemon.handlers._impl_session as session_impl
from shisad.core.atomic_state import durable_append_bytes
from shisad.core.audit import AuditLog
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
