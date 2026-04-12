"""M3 session persistence coverage."""

from __future__ import annotations

import errno
import json
import logging
from collections.abc import Callable
from pathlib import Path

import pytest

import shisad.core.session as session_module
from shisad.core.session import Checkpoint, Session, SessionManager, SessionRehydrateError
from shisad.core.types import (
    Capability,
    SessionId,
    SessionMode,
    SessionRole,
    SessionState,
    UserId,
    WorkspaceId,
)
from shisad.scheduler.schema import TaskEnvelope
from shisad.security.lockdown import LockdownLevel, LockdownManager


def _session_state_path(root: Path, session_id: str) -> Path:
    return root / f"{session_id}.json"


def _lockdown_hooks(
    lockdown: LockdownManager,
) -> tuple[
    Callable[[Session], dict[str, object]],
    Callable[[Session, dict[str, object], str], None],
]:
    def _provider(session: Session) -> dict[str, object]:
        return {"lockdown": lockdown.snapshot(session.id)}

    def _restorer(session: Session, record: dict[str, object], _source: str) -> None:
        lockdown.rehydrate(session.id, record.get("lockdown"))

    return _provider, _restorer


def test_m3_session_manager_persists_and_restores_identity_binding(tmp_path: Path) -> None:
    state_dir = tmp_path / "sessions" / "state"
    manager = SessionManager(state_dir=state_dir)
    session = manager.create(
        channel="cli",
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("ws1"),
        capabilities={Capability.FILE_READ},
        metadata={"trust_level": "trusted"},
    )
    manager.set_mode(session.id, SessionMode.ADMIN_CLEANROOM)
    manager.grant_capabilities(
        session.id,
        {Capability.HTTP_REQUEST},
        actor="uid:1000",
        reason="m3-test",
    )

    persisted = _session_state_path(state_dir, str(session.id))
    assert persisted.exists()

    reloaded = SessionManager(state_dir=state_dir)
    restored = reloaded.get(session.id)
    assert restored is not None
    assert restored.state == SessionState.ACTIVE
    assert restored.mode == SessionMode.ADMIN_CLEANROOM
    assert Capability.HTTP_REQUEST in restored.capabilities
    assert reloaded.validate_identity_binding(
        session.id,
        channel="cli",
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("ws1"),
    )


def test_m3_session_manager_terminate_removes_persisted_state(tmp_path: Path) -> None:
    state_dir = tmp_path / "sessions" / "state"
    manager = SessionManager(state_dir=state_dir)
    session = manager.create(
        channel="cli",
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("ws1"),
    )
    persisted = _session_state_path(state_dir, str(session.id))
    assert persisted.exists()

    assert manager.terminate(session.id, reason="done")
    assert not persisted.exists()

    reloaded = SessionManager(state_dir=state_dir)
    assert reloaded.get(session.id) is None


def test_m3_session_manager_persist_supports_external_metadata_updates(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "sessions" / "state"
    manager = SessionManager(state_dir=state_dir)
    session = manager.create(channel="cli")
    session.metadata["delivery_target"] = {"channel": "cli", "recipient": "ops"}
    assert manager.persist(session.id)

    reloaded = SessionManager(state_dir=state_dir)
    restored = reloaded.get(session.id)
    assert restored is not None
    assert restored.metadata.get("delivery_target") == {"channel": "cli", "recipient": "ops"}


def test_m1_session_role_is_immutable_after_creation() -> None:
    session = Session(role=SessionRole.ORCHESTRATOR)

    with pytest.raises(TypeError, match="immutable"):
        session.role = SessionRole.SUBAGENT


def test_m1_session_manager_create_subagent_session_snapshots_parent_scope(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "sessions" / "state"
    manager = SessionManager(state_dir=state_dir)
    parent = manager.create(
        channel="cli",
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("ws1"),
        capabilities={Capability.FILE_READ, Capability.HTTP_REQUEST},
    )

    child = manager.create_subagent_session(
        channel="task",
        user_id=parent.user_id,
        workspace_id=parent.workspace_id,
        parent_session_id=parent.id,
        mode=SessionMode.TASK,
        capabilities={Capability.FILE_READ},
        metadata={"trust_level": "internal"},
    )

    assert child.role == SessionRole.SUBAGENT
    assert child.mode == SessionMode.TASK
    assert child.metadata["parent_session_id"] == str(parent.id)
    assert child.metadata["capability_sync_mode"] == "manual_override"
    assert child.metadata["inherited_context_taint"] == "untrusted"
    assert child.capabilities == {Capability.FILE_READ}
    assert child.session_key != parent.session_key

    reloaded = SessionManager(state_dir=state_dir)
    restored = reloaded.get(child.id)
    assert restored is not None
    assert restored.role == SessionRole.SUBAGENT
    assert restored.metadata["parent_session_id"] == str(parent.id)


def test_m1_pf46_session_persistence_calls_fsync_for_file_and_parent_dir(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fsync_calls: list[int] = []

    def _record_fsync(fd: int) -> None:
        fsync_calls.append(fd)

    monkeypatch.setattr(session_module.os, "fsync", _record_fsync)
    manager = SessionManager(state_dir=tmp_path / "sessions" / "state")
    _ = manager.create(channel="cli")
    assert len(fsync_calls) >= 2


def test_m1_pf46_session_persistence_ignores_enotsup_for_parent_dir_fsync(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fsync_calls = 0

    def _fsync(fd: int) -> None:
        nonlocal fsync_calls
        _ = fd
        fsync_calls += 1
        if fsync_calls >= 2:
            raise OSError(errno.ENOTSUP, "directory fsync unsupported")

    monkeypatch.setattr(session_module.os, "fsync", _fsync)
    state_dir = tmp_path / "sessions" / "state"
    manager = SessionManager(state_dir=state_dir)
    created = manager.create(channel="cli")
    assert _session_state_path(state_dir, str(created.id)).exists()


def test_m3_session_manager_skips_non_utf8_persisted_state_files(tmp_path: Path) -> None:
    state_dir = tmp_path / "sessions" / "state"
    manager = SessionManager(state_dir=state_dir)
    session = manager.create(
        channel="cli",
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("ws1"),
    )
    (state_dir / "corrupt.json").write_bytes(b"\xff\xfe\xfd")

    reloaded = SessionManager(state_dir=state_dir)
    restored = reloaded.get(session.id)
    assert restored is not None
    assert restored.user_id == UserId("alice")


def test_m3_session_manager_persist_returns_false_for_unserializable_metadata(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "sessions" / "state"
    manager = SessionManager(state_dir=state_dir)
    session = manager.create(channel="cli")
    session.metadata["unserializable"] = object()

    assert not manager.persist(session.id)

    reloaded = SessionManager(state_dir=state_dir)
    restored = reloaded.get(session.id)
    assert restored is not None
    assert "unserializable" not in restored.metadata


def test_m6_session_manager_backfills_legacy_empty_capabilities_on_restore(tmp_path: Path) -> None:
    state_dir = tmp_path / "sessions" / "state"
    state_dir.mkdir(parents=True, exist_ok=True)
    legacy = Session(
        id=SessionId("legacy-empty"),
        channel="cli",
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("ws1"),
        capabilities=set(),
        metadata={"trust_level": "trusted"},
    )
    _session_state_path(state_dir, str(legacy.id)).write_text(
        legacy.model_dump_json(indent=2),
        encoding="utf-8",
    )

    restored_manager = SessionManager(
        state_dir=state_dir,
        default_capabilities={Capability.FILE_READ, Capability.HTTP_REQUEST},
    )
    restored = restored_manager.get(legacy.id)
    assert restored is not None
    assert restored.capabilities == {Capability.FILE_READ, Capability.HTTP_REQUEST}
    assert restored.metadata.get("capability_sync_mode") == "policy_default"


def test_m6_session_manager_preserves_legacy_nonempty_capabilities_as_manual_override(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "sessions" / "state"
    state_dir.mkdir(parents=True, exist_ok=True)
    legacy = Session(
        id=SessionId("legacy-nonempty"),
        channel="cli",
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("ws1"),
        capabilities={Capability.FILE_READ},
        metadata={"trust_level": "trusted"},
    )
    _session_state_path(state_dir, str(legacy.id)).write_text(
        legacy.model_dump_json(indent=2),
        encoding="utf-8",
    )

    restored_manager = SessionManager(
        state_dir=state_dir,
        default_capabilities={Capability.HTTP_REQUEST},
    )
    restored = restored_manager.get(legacy.id)
    assert restored is not None
    assert restored.capabilities == {Capability.FILE_READ}
    assert restored.metadata.get("capability_sync_mode") == "manual_override"


def test_lt1_session_manager_migrates_legacy_default_cli_trust_level(tmp_path: Path) -> None:
    state_dir = tmp_path / "sessions" / "state"
    state_dir.mkdir(parents=True, exist_ok=True)
    legacy = Session(
        id=SessionId("legacy-cli-untrusted"),
        channel="cli",
        user_id=UserId("ops"),
        workspace_id=WorkspaceId("local"),
        mode=SessionMode.DEFAULT,
        role=SessionRole.ORCHESTRATOR,
        capabilities={Capability.FILE_READ},
        metadata={"trust_level": "untrusted"},
    )
    _session_state_path(state_dir, str(legacy.id)).write_text(
        legacy.model_dump_json(indent=2),
        encoding="utf-8",
    )

    restored_manager = SessionManager(state_dir=state_dir)
    restored = restored_manager.get(legacy.id)
    assert restored is not None
    assert restored.metadata["trust_level"] == "trusted"


def test_lt1_session_manager_does_not_upgrade_mediated_or_task_sessions(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "sessions" / "state"
    state_dir.mkdir(parents=True, exist_ok=True)
    mediated = Session(
        id=SessionId("legacy-matrix-untrusted"),
        channel="matrix",
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("room"),
        mode=SessionMode.DEFAULT,
        role=SessionRole.ORCHESTRATOR,
        capabilities={Capability.FILE_READ},
        metadata={"trust_level": "untrusted"},
    )
    task = Session(
        id=SessionId("legacy-cli-task"),
        channel="cli",
        user_id=UserId("ops"),
        workspace_id=WorkspaceId("local"),
        mode=SessionMode.TASK,
        role=SessionRole.SUBAGENT,
        capabilities={Capability.FILE_READ},
        metadata={"trust_level": "untrusted"},
    )
    for session in (mediated, task):
        _session_state_path(state_dir, str(session.id)).write_text(
            session.model_dump_json(indent=2),
            encoding="utf-8",
        )

    restored_manager = SessionManager(state_dir=state_dir)
    restored_mediated = restored_manager.get(mediated.id)
    restored_task = restored_manager.get(task.id)
    assert restored_mediated is not None
    assert restored_task is not None
    assert restored_mediated.metadata["trust_level"] == "untrusted"
    assert restored_task.metadata["trust_level"] == "untrusted"


def test_m6_session_manager_syncs_policy_default_marked_sessions_to_current_defaults(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "sessions" / "state"
    state_dir.mkdir(parents=True, exist_ok=True)
    session = Session(
        id=SessionId("policy-default-sync"),
        channel="cli",
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("ws1"),
        capabilities={Capability.FILE_READ},
        metadata={"capability_sync_mode": "policy_default"},
    )
    _session_state_path(state_dir, str(session.id)).write_text(
        session.model_dump_json(indent=2),
        encoding="utf-8",
    )

    restored_manager = SessionManager(
        state_dir=state_dir,
        default_capabilities={Capability.HTTP_REQUEST},
    )
    restored = restored_manager.get(session.id)
    assert restored is not None
    assert restored.capabilities == {Capability.HTTP_REQUEST}
    assert restored.metadata.get("capability_sync_mode") == "policy_default"


def test_m6_session_manager_syncs_policy_default_sessions_to_empty_defaults(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "sessions" / "state"
    state_dir.mkdir(parents=True, exist_ok=True)
    session = Session(
        id=SessionId("policy-default-empty-target"),
        channel="cli",
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("ws1"),
        capabilities={Capability.FILE_READ, Capability.HTTP_REQUEST},
        metadata={"capability_sync_mode": "policy_default"},
    )
    _session_state_path(state_dir, str(session.id)).write_text(
        session.model_dump_json(indent=2),
        encoding="utf-8",
    )

    restored_manager = SessionManager(
        state_dir=state_dir,
        default_capabilities=set(),
    )
    restored = restored_manager.get(session.id)
    assert restored is not None
    assert restored.capabilities == set()
    assert restored.metadata.get("capability_sync_mode") == "policy_default"


def test_m6_session_manager_legacy_empty_sessions_mark_policy_default_when_defaults_empty(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "sessions" / "state"
    state_dir.mkdir(parents=True, exist_ok=True)
    legacy = Session(
        id=SessionId("legacy-empty-defaults-empty"),
        channel="cli",
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("ws1"),
        capabilities=set(),
        metadata={"trust_level": "trusted"},
    )
    _session_state_path(state_dir, str(legacy.id)).write_text(
        legacy.model_dump_json(indent=2),
        encoding="utf-8",
    )

    restored_manager = SessionManager(
        state_dir=state_dir,
        default_capabilities=set(),
    )
    restored = restored_manager.get(legacy.id)
    assert restored is not None
    assert restored.capabilities == set()
    assert restored.metadata.get("capability_sync_mode") == "policy_default"


def test_m6_session_manager_logs_restore_migration_updates_and_skips(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    state_dir = tmp_path / "sessions" / "state"
    state_dir.mkdir(parents=True, exist_ok=True)
    legacy = Session(
        id=SessionId("legacy-log"),
        channel="cli",
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("ws1"),
        capabilities=set(),
        metadata={"trust_level": "trusted"},
    )
    manual = Session(
        id=SessionId("manual-log"),
        channel="cli",
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("ws1"),
        capabilities={Capability.FILE_READ},
        metadata={"capability_sync_mode": "manual_override"},
    )
    _session_state_path(state_dir, str(legacy.id)).write_text(
        legacy.model_dump_json(indent=2),
        encoding="utf-8",
    )
    _session_state_path(state_dir, str(manual.id)).write_text(
        manual.model_dump_json(indent=2),
        encoding="utf-8",
    )

    with caplog.at_level(logging.DEBUG, logger="shisad.core.session"):
        _ = SessionManager(
            state_dir=state_dir,
            default_capabilities={Capability.HTTP_REQUEST},
        )

    info_messages = [
        record.getMessage() for record in caplog.records if record.levelno == logging.INFO
    ]
    debug_messages = [
        record.getMessage() for record in caplog.records if record.levelno == logging.DEBUG
    ]
    assert any(
        "Session restore migration updated legacy-log" in message for message in info_messages
    )
    assert any(
        "Session restore migration decision for legacy-log" in message for message in debug_messages
    )
    assert any(
        "Session restore migration decision for manual-log" in message for message in debug_messages
    )


def test_m1_session_manager_backfills_subagent_role_for_legacy_task_sessions(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "sessions" / "state"
    state_dir.mkdir(parents=True, exist_ok=True)
    legacy = Session(
        id=SessionId("legacy-task"),
        channel="task",
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("ws1"),
        mode=SessionMode.TASK,
        metadata={"parent_session_id": "parent-1"},
    )
    _session_state_path(state_dir, str(legacy.id)).write_text(
        legacy.model_dump_json(indent=2),
        encoding="utf-8",
    )

    restored_manager = SessionManager(state_dir=state_dir)
    restored = restored_manager.get(legacy.id)
    assert restored is not None
    assert restored.role == SessionRole.SUBAGENT


def test_m2_session_manager_persists_versioned_record_and_rehydrates_lockdown(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "sessions" / "state"
    lockdown = LockdownManager()
    provider, restorer = _lockdown_hooks(lockdown)
    manager = SessionManager(
        state_dir=state_dir,
        supplemental_state_provider=provider,
        supplemental_state_restorer=restorer,
    )
    session = manager.create(
        channel="cli",
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("ws1"),
        capabilities={Capability.FILE_READ},
        metadata={"trust_level": "trusted"},
    )
    manager.set_mode(session.id, SessionMode.ADMIN_CLEANROOM)
    lockdown.set_level(
        session.id,
        level=LockdownLevel.CAUTION,
        reason="m2-test",
        trigger="manual",
    )
    assert manager.persist(session.id)

    persisted = json.loads(
        _session_state_path(state_dir, str(session.id)).read_text(encoding="utf-8")
    )
    assert persisted["schema_version"] == 1
    assert persisted["session"]["mode"] == SessionMode.ADMIN_CLEANROOM.value
    assert persisted["lockdown"]["level"] == LockdownLevel.CAUTION.value

    reloaded_lockdown = LockdownManager()
    provider, restorer = _lockdown_hooks(reloaded_lockdown)
    reloaded = SessionManager(
        state_dir=state_dir,
        supplemental_state_provider=provider,
        supplemental_state_restorer=restorer,
    )
    restored = reloaded.get(session.id)
    assert restored is not None
    assert restored.mode == SessionMode.ADMIN_CLEANROOM
    assert reloaded_lockdown.state_for(session.id).level == LockdownLevel.CAUTION


def test_m2_subagent_sessions_do_not_sync_policy_defaults_on_restore(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "sessions" / "state"
    state_dir.mkdir(parents=True, exist_ok=True)
    legacy = Session(
        id=SessionId("subagent-policy-default"),
        channel="task",
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("ws1"),
        mode=SessionMode.TASK,
        role=SessionRole.SUBAGENT,
        capabilities={Capability.FILE_READ},
        metadata={
            "parent_session_id": "parent-1",
            "capability_sync_mode": "policy_default",
            "task_envelope": TaskEnvelope(
                capability_snapshot=frozenset({Capability.FILE_READ}),
                parent_session_id="parent-1",
                orchestrator_provenance="session:parent-1",
                audit_trail_ref="audit-1",
                policy_snapshot_ref="",
                lockdown_state_inheritance="inherit_runtime_restrictions",
            ).model_dump(mode="json"),
        },
    )
    _session_state_path(state_dir, str(legacy.id)).write_text(
        legacy.model_dump_json(indent=2),
        encoding="utf-8",
    )

    restored_manager = SessionManager(
        state_dir=state_dir,
        default_capabilities={Capability.HTTP_REQUEST},
    )
    restored = restored_manager.get(legacy.id)
    assert restored is not None
    assert restored.capabilities == {Capability.FILE_READ}
    assert restored.metadata.get("capability_sync_mode") == "manual_override"


def test_m2_session_manager_rejects_task_envelope_capability_mismatch(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "sessions" / "state"
    state_dir.mkdir(parents=True, exist_ok=True)
    session = Session(
        id=SessionId("task-envelope-mismatch"),
        channel="task",
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("ws1"),
        mode=SessionMode.TASK,
        role=SessionRole.SUBAGENT,
        capabilities={Capability.FILE_READ, Capability.HTTP_REQUEST},
        metadata={
            "parent_session_id": "parent-1",
            "capability_sync_mode": "manual_override",
            "task_envelope": TaskEnvelope(
                capability_snapshot=frozenset({Capability.FILE_READ}),
                parent_session_id="parent-1",
                orchestrator_provenance="session:parent-1",
                audit_trail_ref="audit-1",
                policy_snapshot_ref="",
                lockdown_state_inheritance="inherit_runtime_restrictions",
            ).model_dump(mode="json"),
        },
    )
    record = {
        "schema_version": 1,
        "session": session.model_dump(mode="json"),
        "lockdown": LockdownManager().snapshot(session.id),
    }
    _session_state_path(state_dir, str(session.id)).write_text(
        json.dumps(record, ensure_ascii=True, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    audits: list[tuple[str, dict[str, object]]] = []
    lockdown = LockdownManager()
    provider, restorer = _lockdown_hooks(lockdown)
    restored_manager = SessionManager(
        state_dir=state_dir,
        audit_hook=lambda action, data: audits.append((action, data)),
        supplemental_state_provider=provider,
        supplemental_state_restorer=restorer,
    )
    assert restored_manager.get(session.id) is None
    assert any(
        action == "session.rehydrate_rejected"
        and data.get("reason") == "task_envelope_capability_mismatch"
        for action, data in audits
    )


def test_m2_session_manager_rejects_unsupported_schema_version(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "sessions" / "state"
    state_dir.mkdir(parents=True, exist_ok=True)
    session = Session(id=SessionId("future-schema"))
    record = {
        "schema_version": 99,
        "session": session.model_dump(mode="json"),
    }
    _session_state_path(state_dir, str(session.id)).write_text(
        json.dumps(record, ensure_ascii=True, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    audits: list[tuple[str, dict[str, object]]] = []

    restored_manager = SessionManager(
        state_dir=state_dir,
        audit_hook=lambda action, data: audits.append((action, data)),
    )

    assert restored_manager.get(session.id) is None
    assert any(
        action == "session.rehydrate_rejected"
        and data.get("reason") == "unsupported_schema_version:99"
        for action, data in audits
    )


def test_m2_restore_from_checkpoint_rejects_unsupported_payload_shape(
    tmp_path: Path,
) -> None:
    manager = SessionManager(state_dir=tmp_path / "sessions" / "state")
    checkpoint = Checkpoint(
        session_id=SessionId("bad-shape"),
        state={"unexpected": "payload"},
    )

    with pytest.raises(SessionRehydrateError, match="unsupported_payload_shape"):
        manager.restore_from_checkpoint(checkpoint)


def test_m2_restore_from_checkpoint_rejects_invalid_lockdown_payload(
    tmp_path: Path,
) -> None:
    lockdown = LockdownManager()
    provider, restorer = _lockdown_hooks(lockdown)
    manager = SessionManager(
        state_dir=tmp_path / "sessions" / "state",
        supplemental_state_provider=provider,
        supplemental_state_restorer=restorer,
    )
    session = manager.create(
        channel="cli",
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("ws1"),
    )
    checkpoint = Checkpoint(
        session_id=session.id,
        state={
            "session": session.model_dump(mode="json"),
            "lockdown": "not-a-dict",
        },
    )

    with pytest.raises(SessionRehydrateError, match="invalid_lockdown_payload"):
        manager.restore_from_checkpoint(checkpoint)


def test_m2_restore_from_checkpoint_normalizes_supplemental_restore_failures(
    tmp_path: Path,
) -> None:
    manager = SessionManager(
        state_dir=tmp_path / "sessions" / "state",
        supplemental_state_restorer=lambda _session, _record, _source: (_ for _ in ()).throw(
            ValueError("boom")
        ),
    )
    session = manager.create(
        channel="cli",
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("ws1"),
    )
    checkpoint = Checkpoint(
        session_id=session.id,
        state={"session": session.model_dump(mode="json")},
    )

    with pytest.raises(SessionRehydrateError, match="invalid_supplemental_state"):
        manager.restore_from_checkpoint(checkpoint)
