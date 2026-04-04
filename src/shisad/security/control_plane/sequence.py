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
    observation_count: int = 0


class PhantomDenyRule(BaseModel, frozen=True):
    name: str
    reason_codes: list[str] = Field(default_factory=list)
    threshold: int = 3
    window_seconds: int = 120
    risk_tier: RiskTier = RiskTier.HIGH


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

    def __init__(
        self,
        patterns: list[SequencePattern] | None = None,
        phantom_rules: list[PhantomDenyRule] | None = None,
    ) -> None:
        self._patterns = patterns or list(DEFAULT_SEQUENCE_PATTERNS)
        self._phantom_rules = phantom_rules or []

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

    def analyze_denied_action(
        self,
        *,
        history: SessionActionHistoryStore,
        candidate_record: ActionHistoryRecord,
        now: datetime | None = None,
    ) -> list[SequenceFinding]:
        if candidate_record.observation_kind != "denied_action":
            return []
        session_id = candidate_record.session_id
        if not session_id:
            return []

        current = now or datetime.now(UTC)
        findings: list[SequenceFinding] = []
        for rule in self._phantom_rules:
            if candidate_record.reason_code not in rule.reason_codes:
                continue
            recent = history.for_analysis(
                session_id,
                window_seconds=rule.window_seconds,
                now=current,
                observation_kinds={"denied_action"},
            )
            qualifying = [record for record in recent if record.reason_code in rule.reason_codes]
            if len(qualifying) < rule.threshold:
                continue
            # Compare against the stable analysis key so threshold crossing stays
            # correct even if rows are later copied or reloaded before analysis.
            candidate_key = history.analysis_key(candidate_record)
            prior_count = len(
                [record for record in qualifying if history.analysis_key(record) != candidate_key]
            )
            if prior_count >= rule.threshold:
                continue
            evidence = [
                f"{record.action_kind.value}:{record.reason_code}:{record.tool_name}"
                for record in qualifying[-rule.threshold :]
            ]
            findings.append(
                SequenceFinding(
                    pattern_name=rule.name,
                    risk_tier=rule.risk_tier,
                    reason_code=f"sequence:{rule.name}",
                    evidence=evidence,
                    observation_count=len(qualifying),
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
            records = history.for_analysis(
                session_id,
                window_seconds=pattern.window_seconds,
                now=now,
                observation_kinds={"action"},
            )
        elif pattern.window_actions is not None:
            records = history.for_analysis(
                session_id,
                last_n=pattern.window_actions,
                observation_kinds={"action"},
            )
        else:
            records = history.for_analysis(session_id, observation_kinds={"action"})
        records = list(records)
        records.append(candidate_record)
        records = history.dedupe_for_analysis(records)
        if pattern.window_actions is not None and len(records) > pattern.window_actions:
            records = records[-pattern.window_actions :]
        return records
