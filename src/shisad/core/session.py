"""Session management and checkpoint system.

Sessions are isolated execution contexts. Checkpoints provide crash
recovery and session state snapshots.
"""

from __future__ import annotations

import json
import logging
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from shisad.core.types import Capability, SessionId, SessionState, UserId, WorkspaceId

logger = logging.getLogger(__name__)


class Session(BaseModel):
    """A session represents an isolated execution context."""

    id: SessionId = Field(default_factory=lambda: SessionId(uuid.uuid4().hex))
    channel: str = "cli"
    user_id: UserId = Field(default_factory=lambda: UserId(""))
    workspace_id: WorkspaceId = Field(default_factory=lambda: WorkspaceId(""))
    session_key: str = ""
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    state: SessionState = SessionState.ACTIVE
    capabilities: set[Capability] = Field(default_factory=set)
    metadata: dict[str, Any] = Field(default_factory=dict)

    model_config = {"arbitrary_types_allowed": True}


class SessionManager:
    """Manages session lifecycle.

    Sessions are isolated — no cross-session state leakage.
    """

    def __init__(
        self,
        *,
        audit_hook: Callable[[str, dict[str, Any]], None] | None = None,
    ) -> None:
        self._sessions: dict[SessionId, Session] = {}
        self._audit_hook = audit_hook

    def create(
        self,
        channel: str = "cli",
        user_id: UserId | None = None,
        workspace_id: WorkspaceId | None = None,
        capabilities: set[Capability] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Session:
        """Create a new session."""
        user = user_id or UserId("")
        workspace = workspace_id or WorkspaceId("")
        nonce = uuid.uuid4().hex[:12]
        session_key = f"{workspace}:{user}:{nonce}"
        session = Session(
            channel=channel,
            user_id=user,
            workspace_id=workspace,
            session_key=session_key,
            capabilities=capabilities or set(),
            metadata=metadata or {},
        )
        self._sessions[session.id] = session
        logger.info(
            "Session created: %s (channel=%s, user=%s, workspace=%s)",
            session.id,
            session.channel,
            session.user_id,
            session.workspace_id,
        )
        return session

    def get(self, session_id: SessionId) -> Session | None:
        """Get a session by ID."""
        return self._sessions.get(session_id)

    def list_active(self) -> list[Session]:
        """List all active sessions."""
        return [s for s in self._sessions.values() if s.state == SessionState.ACTIVE]

    def find_by_binding(
        self,
        *,
        channel: str,
        user_id: UserId,
        workspace_id: WorkspaceId,
    ) -> Session | None:
        """Find an active session by immutable identity binding tuple."""
        for session in self._sessions.values():
            if session.state != SessionState.ACTIVE:
                continue
            if (
                session.channel == channel
                and session.user_id == user_id
                and session.workspace_id == workspace_id
            ):
                return session
        return None

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

    def validate_identity_binding(
        self,
        session_id: SessionId,
        *,
        channel: str,
        user_id: UserId,
        workspace_id: WorkspaceId,
    ) -> bool:
        """Validate that a request identity matches the bound session tuple."""
        session = self._sessions.get(session_id)
        if session is None:
            return False
        return (
            session.channel == channel
            and session.user_id == user_id
            and session.workspace_id == workspace_id
        )

    def grant_capabilities(
        self,
        session_id: SessionId,
        capabilities: set[Capability],
        *,
        actor: str,
        reason: str = "",
    ) -> bool:
        """Grant capabilities to a session.

        Capability grants are never self-issued by the agent.
        """
        session = self._sessions.get(session_id)
        if session is None:
            return False
        if actor == "agent" or actor.startswith("agent:"):
            logger.warning(
                "Rejected agent self-grant capability request for session %s",
                session_id,
            )
            return False

        if not (actor.startswith("uid:") or actor.startswith("system:")):
            logger.warning(
                "Rejected untrusted capability grant actor '%s' for session %s",
                actor,
                session_id,
            )
            return False

        before = set(session.capabilities)
        session.capabilities.update(capabilities)
        granted = sorted(c.value for c in (set(session.capabilities) - before))
        if granted and self._audit_hook is not None:
            self._audit_hook(
                "session.capability_granted",
                {
                    "session_id": session_id,
                    "actor": actor,
                    "granted": granted,
                    "reason": reason,
                },
            )
        return True

    def restore_from_checkpoint(self, checkpoint: Checkpoint) -> Session:
        """Restore session state from a checkpoint payload."""
        state = checkpoint.state
        restored: Session
        if isinstance(state, dict):
            if "id" in state:
                restored = Session.model_validate(state)
            elif isinstance(state.get("session"), dict):
                restored = Session.model_validate(state["session"])
            else:
                restored = Session(id=checkpoint.session_id)
                restored.metadata["checkpoint_state"] = state
        else:
            restored = Session(id=checkpoint.session_id)
            restored.metadata["checkpoint_state"] = {"raw": state}
        restored.state = SessionState.ACTIVE
        self._sessions[restored.id] = restored
        logger.info(
            "Session restored from checkpoint: %s (session=%s)",
            checkpoint.checkpoint_id,
            restored.id,
        )
        return restored


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
