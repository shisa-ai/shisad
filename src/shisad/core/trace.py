"""Training-ready trace recorder for LLM request/response capture.

Captures complete per-turn traces (messages sent, LLM response, tool call
decision chains) for conversion to SFT training data. All content fields
are redacted for secrets and PII before writing to disk.

Storage: per-session JSONL at ``data_dir/traces/{session_id}.jsonl``.
"""

from __future__ import annotations

import logging
import os
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from shisad.security.firewall.pii import PIIDetector
from shisad.security.firewall.secrets import redact_ingress_secrets

logger = logging.getLogger(__name__)

_pii_detector = PIIDetector()


def _redact_text(text: str) -> str:
    """Apply secret and PII redaction to a text string."""
    redacted, _ = redact_ingress_secrets(text)
    redacted, _ = _pii_detector.redact(redacted)
    return redacted


# ---------------------------------------------------------------------------
# Pydantic models (frozen where possible for safety)
# ---------------------------------------------------------------------------


class TraceMessage(BaseModel, frozen=True):
    """A single message in the conversation, mirroring OpenAI chat format."""

    role: str
    content: str = ""
    tool_calls: list[dict[str, Any]] = Field(default_factory=list)
    tool_call_id: str | None = None


class TraceToolCall(BaseModel, frozen=True):
    """A tool call proposal with the full decision chain."""

    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    pep_decision: str = ""
    monitor_decision: str = ""
    control_plane_decision: str = ""
    final_decision: str = ""
    executed: bool = False
    execution_success: bool | None = None


class TraceTurn(BaseModel):
    """One complete turn: user message → planner → tool evaluation → response."""

    turn_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    session_id: str = ""
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    user_content: str = ""
    messages_sent: list[TraceMessage] = Field(default_factory=list)
    llm_response: str = ""
    usage: dict[str, int] = Field(default_factory=dict)
    finish_reason: str = ""
    tool_calls: list[TraceToolCall] = Field(default_factory=list)
    assistant_response: str = ""
    model_id: str = ""
    risk_score: float = 0.0
    trust_level: str = ""
    taint_labels: list[str] = Field(default_factory=list)
    duration_ms: float = 0.0


# ---------------------------------------------------------------------------
# Recorder
# ---------------------------------------------------------------------------


class TraceRecorder:
    """Append-only per-session JSONL trace writer with automatic redaction.

    Follows the ``TranscriptStore`` pattern: one file per session, append-only.
    All string content fields are redacted for secrets and PII before write.
    File permissions are restricted to 0o600.
    """

    def __init__(self, traces_dir: Path) -> None:
        self._traces_dir = traces_dir
        self._traces_dir.mkdir(parents=True, exist_ok=True)

    def record(self, turn: TraceTurn) -> None:
        """Redact and append a TraceTurn to the session's trace file."""
        redacted = self._redact_turn(turn)
        path = self._traces_dir / f"{redacted.session_id}.jsonl"
        line = redacted.model_dump_json() + "\n"

        is_new = not path.exists()
        with path.open("a", encoding="utf-8") as handle:
            handle.write(line)
        if is_new:
            try:
                os.chmod(path, 0o600)
            except OSError:
                logger.debug("Could not set trace file permissions: %s", path)

    def read_turns(self, session_id: str) -> list[TraceTurn]:
        """Read all TraceTurns for a session (for testing/export)."""
        path = self._traces_dir / f"{session_id}.jsonl"
        if not path.exists():
            return []
        turns: list[TraceTurn] = []
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            turns.append(TraceTurn.model_validate_json(line))
        return turns

    @staticmethod
    def _redact_turn(turn: TraceTurn) -> TraceTurn:
        """Return a copy of the turn with all content fields redacted."""
        redacted_messages = [
            TraceMessage(
                role=msg.role,
                content=_redact_text(msg.content),
                tool_calls=msg.tool_calls,
                tool_call_id=msg.tool_call_id,
            )
            for msg in turn.messages_sent
        ]
        return TraceTurn(
            turn_id=turn.turn_id,
            session_id=turn.session_id,
            timestamp=turn.timestamp,
            user_content=_redact_text(turn.user_content),
            messages_sent=redacted_messages,
            llm_response=_redact_text(turn.llm_response),
            usage=dict(turn.usage),
            finish_reason=turn.finish_reason,
            tool_calls=list(turn.tool_calls),
            assistant_response=_redact_text(turn.assistant_response),
            model_id=turn.model_id,
            risk_score=turn.risk_score,
            trust_level=turn.trust_level,
            taint_labels=list(turn.taint_labels),
            duration_ms=turn.duration_ms,
        )
