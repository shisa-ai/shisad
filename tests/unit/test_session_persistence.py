"""M3 session persistence coverage."""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from shisad.core.session import Session, SessionManager
from shisad.core.types import Capability, SessionId, SessionMode, SessionState, UserId, WorkspaceId


def _session_state_path(root: Path, session_id: str) -> Path:
    return root / f"{session_id}.json"


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
        "Session restore migration decision for legacy-log" in message
        for message in debug_messages
    )
    assert any(
        "Session restore migration decision for manual-log" in message
        for message in debug_messages
    )
