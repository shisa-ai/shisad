"""Behavioral sequence analyzer for metadata-only control-plane matching."""

from __future__ import annotations

import re
from datetime import UTC, datetime

from pydantic import BaseModel, Field

from shisad.security.control_plane.history import ActionHistoryRecord, SessionActionHistoryStore
from shisad.security.control_plane.schema import ActionKind, ControlPlaneAction, RiskTier


class SequencePattern(BaseModel, frozen=True):
    name: str
    pattern: list[str] = Field(default_factory=list)
    window_actions: int | None = None
    window_seconds: int | None = None
    risk_tier: RiskTier = RiskTier.MEDIUM
    resource_pattern: str | None = None


class SequenceFinding(BaseModel, frozen=True):
    pattern_name: str
    risk_tier: RiskTier
    reason_code: str
    evidence: list[str] = Field(default_factory=list)


DEFAULT_SEQUENCE_PATTERNS: list[SequencePattern] = [
    SequencePattern(
        name="exfil_after_read",
        pattern=[ActionKind.FS_READ.value, ActionKind.EGRESS.value],
        window_actions=5,
        risk_tier=RiskTier.HIGH,
    ),
    SequencePattern(
        name="env_then_egress",
        pattern=[ActionKind.ENV_ACCESS.value, ActionKind.EGRESS.value],
        window_actions=3,
        risk_tier=RiskTier.CRITICAL,
    ),
    SequencePattern(
        name="mass_enum",
        pattern=[
            ActionKind.FS_LIST.value,
            ActionKind.FS_LIST.value,
            ActionKind.FS_LIST.value,
            ActionKind.FS_LIST.value,
        ],
        window_actions=10,
        risk_tier=RiskTier.MEDIUM,
    ),
    SequencePattern(
        name="persistence_attempt",
        pattern=[ActionKind.FS_WRITE.value, ActionKind.SHELL_EXEC.value],
        window_actions=8,
        risk_tier=RiskTier.CRITICAL,
        resource_pattern=r".*(\.rc$|cron|autostart).*",
    ),
    SequencePattern(
        name="rapid_fire",
        pattern=["*", "*", "*", "*", "*"],
        window_seconds=1,
        risk_tier=RiskTier.HIGH,
    ),
]


class BehavioralSequenceAnalyzer:
    """Detects suspicious action sequences using session history windows."""

    def __init__(self, patterns: list[SequencePattern] | None = None) -> None:
        self._patterns = patterns or list(DEFAULT_SEQUENCE_PATTERNS)

    def analyze(
        self,
        *,
        history: SessionActionHistoryStore,
        candidate_action: ControlPlaneAction,
        now: datetime | None = None,
    ) -> list[SequenceFinding]:
        current = now or datetime.now(UTC)
        session_id = candidate_action.origin.session_id
        if not session_id:
            return []

        candidate_record = ActionHistoryRecord(
            timestamp=candidate_action.timestamp,
            session_id=session_id,
            origin=candidate_action.origin,
            action_kind=candidate_action.action_kind,
            resource_id=candidate_action.resource_id,
            tool_name=candidate_action.tool_name,
        )

        findings: list[SequenceFinding] = []
        for pattern in self._patterns:
            window_records = self._window_records(
                history=history,
                session_id=session_id,
                pattern=pattern,
                candidate_record=candidate_record,
                now=current,
            )
            if not window_records:
                continue
            kinds = [record.action_kind.value for record in window_records]
            if not self._matches_pattern(kinds, pattern.pattern):
                continue
            if pattern.resource_pattern:
                matcher = re.compile(pattern.resource_pattern, flags=re.IGNORECASE)
                if not any(matcher.search(record.resource_id) for record in window_records):
                    continue
            findings.append(
                SequenceFinding(
                    pattern_name=pattern.name,
                    risk_tier=pattern.risk_tier,
                    reason_code=f"sequence:{pattern.name}",
                    evidence=kinds,
                )
            )
        return findings

    @staticmethod
    def _matches_pattern(kinds: list[str], pattern: list[str]) -> bool:
        if len(kinds) < len(pattern):
            return False
        index = 0
        for observed in kinds:
            if index >= len(pattern):
                return True
            expected = pattern[index]
            if expected == "*" or observed == expected:
                index += 1
        return index == len(pattern)

    @staticmethod
    def _window_records(
        *,
        history: SessionActionHistoryStore,
        session_id: str,
        pattern: SequencePattern,
        candidate_record: ActionHistoryRecord,
        now: datetime,
    ) -> list[ActionHistoryRecord]:
        records: list[ActionHistoryRecord]
        if pattern.window_seconds is not None:
            records = history.in_window(session_id, pattern.window_seconds, now=now)
        elif pattern.window_actions is not None:
            records = history.last_n(session_id, pattern.window_actions)
        else:
            records = history.all_for_session(session_id)
        records = list(records)
        records.append(candidate_record)
        if pattern.window_actions is not None and len(records) > pattern.window_actions:
            records = records[-pattern.window_actions :]
        return records
