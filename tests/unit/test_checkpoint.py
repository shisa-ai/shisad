"""M0.T10: Checkpoint create/restore round-trips correctly."""

from __future__ import annotations

from pathlib import Path

import pytest

from shisad.core.session import CheckpointStore, Session
from shisad.core.types import SessionId, UserId
from shisad.security.lockdown import LockdownLevel, LockdownManager


@pytest.fixture
def checkpoint_store(tmp_path: Path) -> CheckpointStore:
    return CheckpointStore(tmp_path / "checkpoints")


class TestCheckpointRoundTrip:
    """M0.T10: checkpoint create/restore round-trips correctly."""

    def test_create_and_restore(self, checkpoint_store: CheckpointStore) -> None:
        session = Session(
            id=SessionId("test_session"),
            user_id=UserId("test_user"),
            metadata={"key": "value"},
        )
        checkpoint = checkpoint_store.create(session)

        restored = checkpoint_store.restore(checkpoint.checkpoint_id)
        assert restored is not None
        assert restored.session_id == SessionId("test_session")
        assert restored.state["user_id"] == "test_user"
        assert restored.state["metadata"]["key"] == "value"

    def test_restore_nonexistent(self, checkpoint_store: CheckpointStore) -> None:
        result = checkpoint_store.restore("nonexistent_id")
        assert result is None

    def test_list_for_session(self, checkpoint_store: CheckpointStore) -> None:
        session = Session(id=SessionId("s1"), user_id=UserId("u1"))

        checkpoint_store.create(session, state={"step": 1})
        checkpoint_store.create(session, state={"step": 2})

        checkpoints = checkpoint_store.list_for_session(SessionId("s1"))
        assert len(checkpoints) == 2
        # Newest first
        assert checkpoints[0].state["step"] == 2

    def test_different_sessions_isolated(self, checkpoint_store: CheckpointStore) -> None:
        s1 = Session(id=SessionId("s1"), user_id=UserId("u1"))
        s2 = Session(id=SessionId("s2"), user_id=UserId("u2"))

        checkpoint_store.create(s1)
        checkpoint_store.create(s2)

        assert len(checkpoint_store.list_for_session(SessionId("s1"))) == 1
        assert len(checkpoint_store.list_for_session(SessionId("s2"))) == 1

    def test_m2_checkpoint_store_enriches_state_with_lockdown_snapshot(
        self,
        tmp_path: Path,
    ) -> None:
        lockdown = LockdownManager()
        session = Session(
            id=SessionId("lockdown-session"),
            user_id=UserId("alice"),
        )
        lockdown.set_level(
            session.id,
            level=LockdownLevel.CAUTION,
            reason="checkpoint-test",
            trigger="manual",
        )
        store = CheckpointStore(
            tmp_path / "checkpoints",
            supplemental_state_provider=lambda current: {"lockdown": lockdown.snapshot(current.id)},
        )

        checkpoint = store.create(session)

        assert checkpoint.state["session"]["id"] == "lockdown-session"
        assert checkpoint.state["lockdown"]["level"] == LockdownLevel.CAUTION.value

    def test_m2_checkpoint_store_preserves_provided_lockdown_state(
        self,
        tmp_path: Path,
    ) -> None:
        current_lockdown = LockdownManager()
        session = Session(
            id=SessionId("archive-import-session"),
            user_id=UserId("alice"),
        )
        current_lockdown.set_level(
            session.id,
            level=LockdownLevel.NORMAL,
            reason="current-runtime",
            trigger="manual",
        )
        store = CheckpointStore(
            tmp_path / "checkpoints",
            supplemental_state_provider=lambda current: {
                "lockdown": current_lockdown.snapshot(current.id)
            },
        )
        archived_lockdown = {
            "session_id": str(session.id),
            "level": LockdownLevel.FULL_LOCKDOWN.value,
            "reason": "archived",
            "trigger": "manual",
            "updated_at": "2026-04-02T00:00:00+00:00",
        }

        checkpoint = store.create(
            session,
            state={
                "session": session.model_dump(mode="json"),
                "lockdown": archived_lockdown,
            },
        )

        assert checkpoint.state["lockdown"]["level"] == LockdownLevel.FULL_LOCKDOWN.value
        assert checkpoint.state["lockdown"]["reason"] == "archived"
