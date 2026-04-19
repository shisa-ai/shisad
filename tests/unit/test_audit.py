"""M0.T6-T8: Audit log hash-chain detects insertion, modification, deletion."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from shisad.core.audit import AuditLog
from shisad.core.events import (
    A2aIngressEvaluated,
    AnomalyReported,
    SessionCreated,
    ToolApproved,
    ToolRejected,
)
from shisad.core.types import PEPDecisionKind, SessionId, ToolName, UserId


@pytest.fixture
def audit_path(tmp_path: Path) -> Path:
    return tmp_path / "audit.jsonl"


@pytest.fixture
def audit_log(audit_path: Path) -> AuditLog:
    return AuditLog(audit_path)


async def _write_entries(log: AuditLog, count: int = 3) -> None:
    for i in range(count):
        event = SessionCreated(
            session_id=SessionId(f"session_{i}"),
            user_id=UserId(f"user_{i}"),
            actor="test",
        )
        await log.persist(event)


class TestAuditHashChainInsertion:
    """M0.T6: audit log hash-chain detects insertion."""

    @pytest.mark.asyncio
    async def test_valid_chain(self, audit_log: AuditLog, audit_path: Path) -> None:
        await _write_entries(audit_log)
        is_valid, count, error = audit_log.verify_chain()
        assert is_valid
        assert count == 3
        assert error == ""

    @pytest.mark.asyncio
    async def test_insertion_detected(self, audit_log: AuditLog, audit_path: Path) -> None:
        await _write_entries(audit_log)

        # Insert a fake entry in the middle
        lines = audit_path.read_text().splitlines()
        fake = json.loads(lines[0])
        fake["event_id"] = "inserted_fake"
        lines.insert(1, json.dumps(fake))
        audit_path.write_text("\n".join(lines) + "\n")

        is_valid, _count, error = audit_log.verify_chain()
        assert not is_valid
        assert "chain break" in error


class TestAuditHashChainModification:
    """M0.T7: audit log hash-chain detects modification."""

    @pytest.mark.asyncio
    async def test_modification_detected(self, audit_log: AuditLog, audit_path: Path) -> None:
        await _write_entries(audit_log)

        # Modify the second entry
        lines = audit_path.read_text().splitlines()
        entry = json.loads(lines[1])
        entry["data"]["actor"] = "tampered"
        lines[1] = json.dumps(entry)
        audit_path.write_text("\n".join(lines) + "\n")

        is_valid, _count, error = audit_log.verify_chain()
        assert not is_valid
        # Could be a data hash mismatch or a chain break depending on what was modified
        assert "mismatch" in error or "chain break" in error


class TestAuditHashChainDeletion:
    """M0.T8: audit log hash-chain detects deletion."""

    @pytest.mark.asyncio
    async def test_deletion_detected(self, audit_log: AuditLog, audit_path: Path) -> None:
        await _write_entries(audit_log)

        # Delete the second entry
        lines = audit_path.read_text().splitlines()
        del lines[1]
        audit_path.write_text("\n".join(lines) + "\n")

        is_valid, _count, error = audit_log.verify_chain()
        assert not is_valid
        assert "chain break" in error


class TestAuditEntryMetadataDerivation:
    """PLN-M3: exercise `_derive_entry_metadata` branches.

    Before this class the audit tests only covered hash-chain integrity;
    the structured action/target/decision/reasoning fields were populated
    but never asserted, so a regression that dropped or swapped them would
    have gone unnoticed.
    """

    @pytest.mark.asyncio
    async def test_tool_approved_has_allow_decision_and_tool_target(
        self, audit_log: AuditLog, audit_path: Path
    ) -> None:
        await audit_log.persist(
            ToolApproved(
                session_id=SessionId("s1"),
                actor="pep",
                tool_name=ToolName("fs.read"),
                decision=PEPDecisionKind.ALLOW,
            )
        )
        entry = json.loads(audit_path.read_text().splitlines()[0])
        assert entry["event_type"] == "ToolApproved"
        assert entry["action"] == "ToolApproved"
        assert entry["target"] == "fs.read"
        assert entry["decision"] == "allow"

    @pytest.mark.asyncio
    async def test_tool_rejected_carries_reject_decision_and_reason(
        self, audit_log: AuditLog, audit_path: Path
    ) -> None:
        await audit_log.persist(
            ToolRejected(
                session_id=SessionId("s1"),
                actor="pep",
                tool_name=ToolName("shell.exec"),
                decision=PEPDecisionKind.REJECT,
                reason="shell not permitted",
            )
        )
        entry = json.loads(audit_path.read_text().splitlines()[0])
        assert entry["decision"] == "reject"
        assert entry["target"] == "shell.exec"
        assert entry["reasoning"] == "shell not permitted"

    @pytest.mark.asyncio
    async def test_anomaly_reported_reasoning_falls_back_to_description(
        self, audit_log: AuditLog, audit_path: Path
    ) -> None:
        await audit_log.persist(
            AnomalyReported(
                session_id=SessionId("s1"),
                actor="planner",
                severity="warning",
                description="suspicious prompt fragment observed",
                recommended_action="retry_or_report",
            )
        )
        entry = json.loads(audit_path.read_text().splitlines()[0])
        assert entry["action"] == "AnomalyReported"
        assert entry["reasoning"] == "suspicious prompt fragment observed"

    @pytest.mark.asyncio
    async def test_a2a_ingress_accepted_outcome_maps_to_allow_and_sender_target(
        self, audit_log: AuditLog, audit_path: Path
    ) -> None:
        await audit_log.persist(
            A2aIngressEvaluated(
                session_id=SessionId("s1"),
                actor="a2a_ingress",
                sender_agent_id="agent-42",
                outcome="accepted",
            )
        )
        entry = json.loads(audit_path.read_text().splitlines()[0])
        assert entry["decision"] == "allow"
        assert entry["target"] == "agent-42"

    @pytest.mark.asyncio
    async def test_a2a_ingress_non_accepted_outcome_maps_to_reject(
        self, audit_log: AuditLog, audit_path: Path
    ) -> None:
        await audit_log.persist(
            A2aIngressEvaluated(
                session_id=SessionId("s1"),
                actor="a2a_ingress",
                sender_agent_id="agent-42",
                outcome="rate_limited",
            )
        )
        entry = json.loads(audit_path.read_text().splitlines()[0])
        assert entry["decision"] == "reject"


class TestAuditResumeChain:
    """PLN-M3: resuming from an existing log must continue the hash chain."""

    @pytest.mark.asyncio
    async def test_resume_chain_continues_existing_hash_line(self, audit_path: Path) -> None:
        first = AuditLog(audit_path)
        await _write_entries(first, count=2)
        expected_previous = first._previous_hash
        expected_count = first.entry_count

        reopened = AuditLog(audit_path)

        assert reopened.entry_count == expected_count
        assert reopened._previous_hash == expected_previous
        # A subsequent persist must chain from the resumed previous hash, so
        # the overall log still verifies cleanly.
        await _write_entries(reopened, count=1)
        ok, total, error = reopened.verify_chain()
        assert ok, error
        assert total == expected_count + 1


class TestAuditQueryFilters:
    """PLN-M3: exercise `query` filters (event_type, session_id, actor, since,
    limit, tail)."""

    async def _seed_mixed_events(self, log: AuditLog) -> None:
        await log.persist(
            SessionCreated(
                session_id=SessionId("sA"),
                user_id=UserId("alice"),
                actor="session",
            )
        )
        await asyncio.sleep(0.001)
        await log.persist(
            ToolRejected(
                session_id=SessionId("sA"),
                actor="pep",
                tool_name=ToolName("shell.exec"),
                reason="no capability",
            )
        )
        await asyncio.sleep(0.001)
        await log.persist(
            ToolApproved(
                session_id=SessionId("sB"),
                actor="pep",
                tool_name=ToolName("fs.read"),
            )
        )

    @pytest.mark.asyncio
    async def test_query_filters_by_event_type(self, audit_log: AuditLog) -> None:
        await self._seed_mixed_events(audit_log)
        rejected = audit_log.query(event_type="ToolRejected")
        assert len(rejected) == 1
        assert rejected[0]["event_type"] == "ToolRejected"

    @pytest.mark.asyncio
    async def test_query_filters_by_session_id(self, audit_log: AuditLog) -> None:
        await self._seed_mixed_events(audit_log)
        scoped = audit_log.query(session_id="sB")
        assert {entry["session_id"] for entry in scoped} == {"sB"}

    @pytest.mark.asyncio
    async def test_query_filters_by_actor(self, audit_log: AuditLog) -> None:
        await self._seed_mixed_events(audit_log)
        from_pep = audit_log.query(actor="pep")
        assert all(entry["actor"] == "pep" for entry in from_pep)
        assert len(from_pep) == 2

    @pytest.mark.asyncio
    async def test_query_since_excludes_older_entries(self, audit_log: AuditLog) -> None:
        await self._seed_mixed_events(audit_log)
        future = datetime.now(UTC) + timedelta(minutes=1)
        assert audit_log.query(since=future) == []

    @pytest.mark.asyncio
    async def test_query_limit_truncates_head(self, audit_log: AuditLog) -> None:
        await self._seed_mixed_events(audit_log)
        head = audit_log.query(limit=2)
        assert len(head) == 2
        assert head[0]["event_type"] == "SessionCreated"

    @pytest.mark.asyncio
    async def test_query_tail_keeps_most_recent(self, audit_log: AuditLog) -> None:
        await self._seed_mixed_events(audit_log)
        tail = audit_log.query(limit=2, tail=True)
        assert len(tail) == 2
        # The most recent entry is a ToolApproved for session sB.
        assert tail[-1]["event_type"] == "ToolApproved"
        assert tail[-1]["session_id"] == "sB"

    def test_query_returns_empty_when_log_missing(self, tmp_path: Path) -> None:
        log = AuditLog(tmp_path / "missing.jsonl")
        assert log.query() == []


class TestAuditParseSince:
    """PLN-M3: `parse_since` normalizes operator inputs into query filters."""

    def test_parse_since_relative_units(self) -> None:
        now = datetime(2026, 4, 16, 12, 0, 0, tzinfo=UTC)
        assert AuditLog.parse_since("30s", now=now) == now - timedelta(seconds=30)
        assert AuditLog.parse_since("15m", now=now) == now - timedelta(minutes=15)
        assert AuditLog.parse_since("2h", now=now) == now - timedelta(hours=2)
        assert AuditLog.parse_since("7d", now=now) == now - timedelta(days=7)

    def test_parse_since_iso_z_suffix_is_utc(self) -> None:
        parsed = AuditLog.parse_since("2026-02-09T12:00:00Z")
        assert parsed == datetime(2026, 2, 9, 12, 0, 0, tzinfo=UTC)

    def test_parse_since_bare_date_assumes_utc(self) -> None:
        parsed = AuditLog.parse_since("2026-02-09")
        assert parsed == datetime(2026, 2, 9, 0, 0, 0, tzinfo=UTC)

    def test_parse_since_invalid_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="Invalid --since"):
            AuditLog.parse_since("not-a-duration")

    def test_parse_since_empty_returns_none(self) -> None:
        assert AuditLog.parse_since(None) is None
        assert AuditLog.parse_since("") is None
        assert AuditLog.parse_since("   ") is None
