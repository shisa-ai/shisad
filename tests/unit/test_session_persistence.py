"""M3 session persistence coverage."""

from __future__ import annotations

from pathlib import Path

from shisad.core.session import SessionManager
from shisad.core.types import Capability, SessionMode, SessionState, UserId, WorkspaceId


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
