"""Session management and checkpoint system.

Sessions are isolated execution contexts. Checkpoints provide crash
recovery and session state snapshots.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from shisad.core.types import Capability, SessionId, SessionState, UserId, WorkspaceId

logger = logging.getLogger(__name__)


class Session(BaseModel):
    """A session represents an isolated execution context."""

    id: SessionId = Field(default_factory=lambda: SessionId(uuid.uuid4().hex))
    user_id: UserId = Field(default_factory=lambda: UserId(""))
    workspace_id: WorkspaceId = Field(default_factory=lambda: WorkspaceId(""))
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    state: SessionState = SessionState.ACTIVE
    capabilities: set[Capability] = Field(default_factory=set)
    metadata: dict[str, Any] = Field(default_factory=dict)

    model_config = {"arbitrary_types_allowed": True}


class SessionManager:
    """Manages session lifecycle.

    Sessions are isolated — no cross-session state leakage.
    """

    def __init__(self) -> None:
        self._sessions: dict[SessionId, Session] = {}

    def create(
        self,
        user_id: UserId | None = None,
        workspace_id: WorkspaceId | None = None,
        capabilities: set[Capability] | None = None,
    ) -> Session:
        """Create a new session."""
        session = Session(
            user_id=user_id or UserId(""),
            workspace_id=workspace_id or WorkspaceId(""),
            capabilities=capabilities or set(),
        )
        self._sessions[session.id] = session
        logger.info("Session created: %s (user: %s)", session.id, session.user_id)
        return session

    def get(self, session_id: SessionId) -> Session | None:
        """Get a session by ID."""
        return self._sessions.get(session_id)

    def list_active(self) -> list[Session]:
        """List all active sessions."""
        return [s for s in self._sessions.values() if s.state == SessionState.ACTIVE]

    def terminate(self, session_id: SessionId, reason: str = "") -> bool:
        """Terminate a session."""
        session = self._sessions.get(session_id)
        if session is None:
            return False
        session.state = SessionState.TERMINATED
        logger.info("Session terminated: %s (reason: %s)", session_id, reason)
        return True

    def suspend(self, session_id: SessionId) -> bool:
        """Suspend a session (can be resumed later)."""
        session = self._sessions.get(session_id)
        if session is None:
            return False
        session.state = SessionState.SUSPENDED
        return True

    def resume(self, session_id: SessionId) -> bool:
        """Resume a suspended session."""
        session = self._sessions.get(session_id)
        if session is None or session.state != SessionState.SUSPENDED:
            return False
        session.state = SessionState.ACTIVE
        return True


# --- Checkpoint system ---


class Checkpoint(BaseModel):
    """A snapshot of session state for crash recovery."""

    checkpoint_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    session_id: SessionId
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    state: dict[str, Any] = Field(default_factory=dict)


class CheckpointStore:
    """Stores and retrieves session state checkpoints.

    Checkpoints are JSON files in a designated directory. This is session
    state recovery, not workspace/filesystem rollback (that lands in M3).
    """

    def __init__(self, checkpoint_dir: Path) -> None:
        self._dir = checkpoint_dir
        self._dir.mkdir(parents=True, exist_ok=True)

    def create(self, session: Session, state: dict[str, Any] | None = None) -> Checkpoint:
        """Create a checkpoint of the current session state."""
        checkpoint = Checkpoint(
            session_id=session.id,
            state=state or session.model_dump(mode="json"),
        )

        path = self._checkpoint_path(checkpoint.checkpoint_id)
        path.write_text(checkpoint.model_dump_json(indent=2))

        logger.debug(
            "Checkpoint created: %s (session: %s)", checkpoint.checkpoint_id, session.id
        )
        return checkpoint

    def restore(self, checkpoint_id: str) -> Checkpoint | None:
        """Restore a checkpoint by ID."""
        path = self._checkpoint_path(checkpoint_id)
        if not path.exists():
            return None
        return Checkpoint.model_validate_json(path.read_text())

    def list_for_session(self, session_id: SessionId) -> list[Checkpoint]:
        """List all checkpoints for a session, newest first."""
        checkpoints: list[Checkpoint] = []
        if not self._dir.exists():
            return checkpoints

        for path in self._dir.glob("*.json"):
            try:
                data = json.loads(path.read_text())
                if data.get("session_id") == session_id:
                    checkpoints.append(Checkpoint.model_validate(data))
            except Exception:
                logger.warning("Invalid checkpoint file: %s", path)

        return sorted(checkpoints, key=lambda c: c.created_at, reverse=True)

    def _checkpoint_path(self, checkpoint_id: str) -> Path:
        return self._dir / f"{checkpoint_id}.json"
