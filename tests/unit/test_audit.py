"""M0.T6-T8: Audit log hash-chain detects insertion, modification, deletion."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import NoReturn

import pytest

from shisad.core.audit import AuditIntegrityError, AuditLog, AuditUnavailableError
from shisad.core.events import (
    A2aIngressEvaluated,
    AnomalyReported,
    SessionCreated,
    ToolApproved,
    ToolRejected,
)
from shisad.core.types import EventId, PEPDecisionKind, SessionId, ToolName, UserId


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


def _entry_lines(path: Path) -> list[str]:
    return [
        line
        for line in path.read_text(encoding="utf-8").splitlines()
        if json.loads(line).get("record_type") != "shisad.audit.segment"
    ]


@pytest.mark.asyncio
async def test_recovery_event_id_is_idempotent_across_audit_restart(
    audit_path: Path,
) -> None:
    event_id = EventId("recovery-accounting-event")
    event_timestamp = datetime(2026, 7, 12, 18, 30, tzinfo=UTC)
    first = AuditLog(audit_path)
    await first.persist(
        ToolRejected(
            event_id=event_id,
            timestamp=event_timestamp,
            session_id=SessionId("s-recovery"),
            actor="recovery",
            tool_name=ToolName("time.now"),
            reason="uncertain_effect_requires_fresh_approval",
        )
    )

    restarted = AuditLog(audit_path)
    await restarted.persist(
        ToolRejected(
            event_id=event_id,
            timestamp=event_timestamp,
            session_id=SessionId("s-recovery"),
            actor="recovery",
            tool_name=ToolName("time.now"),
            reason="uncertain_effect_requires_fresh_approval",
        )
    )

    assert restarted.entry_count == 1
    assert len(_entry_lines(audit_path)) == 1
    assert restarted.verify_chain() == (True, 1, "")


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
        entry_index = next(
            index
            for index, line in enumerate(lines)
            if json.loads(line).get("record_type") != "shisad.audit.segment"
        )
        fake = json.loads(lines[entry_index])
        fake["event_id"] = "inserted_fake"
        lines.insert(entry_index + 1, json.dumps(fake))
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
        entry_indexes = [
            index
            for index, line in enumerate(lines)
            if json.loads(line).get("record_type") != "shisad.audit.segment"
        ]
        entry = json.loads(lines[entry_indexes[1]])
        entry["data"]["actor"] = "tampered"
        lines[entry_indexes[1]] = json.dumps(entry)
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
        entry_indexes = [
            index
            for index, line in enumerate(lines)
            if json.loads(line).get("record_type") != "shisad.audit.segment"
        ]
        del lines[entry_indexes[1]]
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
        entry = json.loads(_entry_lines(audit_path)[0])
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
        entry = json.loads(_entry_lines(audit_path)[0])
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
        entry = json.loads(_entry_lines(audit_path)[0])
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
        entry = json.loads(_entry_lines(audit_path)[0])
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
        entry = json.loads(_entry_lines(audit_path)[0])
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


class TestAuditLifecycle:
    @pytest.mark.asyncio
    async def test_constructor_refuses_corrupt_existing_chain(self, audit_path: Path) -> None:
        first = AuditLog(audit_path)
        await _write_entries(first, count=2)
        lines = audit_path.read_text(encoding="utf-8").splitlines()
        entry_index = next(
            index
            for index, line in enumerate(lines)
            if json.loads(line).get("record_type") != "shisad.audit.segment"
        )
        row = json.loads(lines[entry_index])
        row["data_hash"] = "tampered"
        lines[entry_index] = json.dumps(row)
        audit_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        with pytest.raises(AuditIntegrityError, match="data hash mismatch"):
            AuditLog(audit_path)

    @pytest.mark.asyncio
    async def test_constructor_refuses_partial_final_row(self, audit_path: Path) -> None:
        log = AuditLog(audit_path)
        await _write_entries(log, count=1)
        payload = audit_path.read_bytes()
        assert payload.endswith(b"\n")
        audit_path.write_bytes(payload[:-1])

        with pytest.raises(AuditIntegrityError, match="partial audit row"):
            AuditLog(audit_path)

    @pytest.mark.asyncio
    async def test_rotation_retention_restart_and_query_span_segments(
        self, audit_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("shisad.core.audit.MAX_SEGMENT_BYTES", 1_200)
        monkeypatch.setattr("shisad.core.audit.MAX_ARCHIVES", 2)
        log = AuditLog(audit_path)
        for index in range(8):
            await log.persist(
                SessionCreated(
                    session_id=SessionId(f"rotated-{index}"),
                    user_id=UserId(f"user-{index}"),
                    actor="rotation-test",
                )
            )

        archives = sorted(tmp_path for tmp_path in audit_path.parent.glob("audit.*.jsonl"))
        assert 1 <= len(archives) <= 2
        status = log.lifecycle_status
        assert status["state"] == "verified"
        assert status["archive_count"] == len(archives)
        assert status["segment_count"] == len(archives) + 1
        assert status["retained_bytes"] <= 3 * 1_200

        restarted = AuditLog(audit_path)
        assert restarted.verify_chain()[0] is True
        rows = restarted.query(actor="rotation-test", limit=100)
        assert rows
        assert rows[-1]["session_id"] == "rotated-7"
        assert [row["timestamp"] for row in rows] == sorted(row["timestamp"] for row in rows)

    @pytest.mark.asyncio
    async def test_restart_reconstructs_missing_active_successor(
        self, audit_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("shisad.core.audit.MAX_SEGMENT_BYTES", 1_200)
        log = AuditLog(audit_path)
        await _write_entries(log, count=2)
        header = json.loads(audit_path.read_text(encoding="utf-8").splitlines()[0])
        sequence = int(header["sequence"])
        archive = audit_path.with_name(f"audit.{sequence:020d}.jsonl")
        os.replace(audit_path, archive)

        restarted = AuditLog(audit_path)

        assert audit_path.exists()
        assert restarted.verify_chain()[0] is True
        successor = json.loads(audit_path.read_text(encoding="utf-8").splitlines()[0])
        assert successor["sequence"] == sequence + 1
        assert successor["previous_segment_sha256"]

    @pytest.mark.asyncio
    async def test_missing_middle_archive_refuses_admission(
        self, audit_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("shisad.core.audit.MAX_SEGMENT_BYTES", 1_200)
        log = AuditLog(audit_path)
        await _write_entries(log, count=4)
        archives = sorted(audit_path.parent.glob("audit.*.jsonl"))
        assert len(archives) >= 2
        archives[-1].unlink()

        with pytest.raises(AuditIntegrityError, match="missing middle"):
            AuditLog(audit_path)

    @pytest.mark.asyncio
    async def test_active_segment_requires_its_immediate_predecessor(
        self, audit_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("shisad.core.audit.MAX_SEGMENT_BYTES", 1_200)
        log = AuditLog(audit_path)
        await _write_entries(log, count=4)
        archives = list(audit_path.parent.glob("audit.*.jsonl"))
        assert archives
        for archive in archives:
            archive.unlink()

        with pytest.raises(AuditIntegrityError, match="immediate predecessor"):
            AuditLog(audit_path)

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("header_field", "expected"),
        [
            ("previous_segment_sha256", "file-hash link mismatch"),
            ("previous_terminal_event_hash", "terminal-hash link mismatch"),
        ],
    )
    async def test_adjacent_segment_link_tamper_refuses_admission(
        self,
        audit_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        header_field: str,
        expected: str,
    ) -> None:
        monkeypatch.setattr("shisad.core.audit.MAX_SEGMENT_BYTES", 1_200)
        log = AuditLog(audit_path)
        await _write_entries(log, count=2)
        lines = audit_path.read_text(encoding="utf-8").splitlines()
        header = json.loads(lines[0])
        header[header_field] = "f" * 64
        lines[0] = json.dumps(header, sort_keys=True, separators=(",", ":"))
        if header_field == "previous_terminal_event_hash":
            first_entry = json.loads(lines[1])
            first_entry["previous_event_hash"] = "f" * 64
            first_entry["previous_hash"] = "f" * 64
            lines[1] = json.dumps(first_entry, separators=(",", ":"))
        audit_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        with pytest.raises(AuditIntegrityError, match=expected):
            AuditLog(audit_path)

    @pytest.mark.asyncio
    async def test_archived_row_corruption_refuses_admission(
        self, audit_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("shisad.core.audit.MAX_SEGMENT_BYTES", 1_200)
        log = AuditLog(audit_path)
        await _write_entries(log, count=2)
        archive = sorted(audit_path.parent.glob("audit.*.jsonl"))[0]
        lines = archive.read_text(encoding="utf-8").splitlines()
        entry_index = next(
            index
            for index, line in enumerate(lines)
            if json.loads(line).get("record_type") != "shisad.audit.segment"
        )
        row = json.loads(lines[entry_index])
        row["data_hash"] = "f" * 64
        lines[entry_index] = json.dumps(row, separators=(",", ":"))
        archive.write_text("\n".join(lines) + "\n", encoding="utf-8")

        with pytest.raises(AuditIntegrityError, match="data hash mismatch"):
            AuditLog(audit_path)

    @pytest.mark.asyncio
    async def test_malformed_segment_header_refuses_admission(self, audit_path: Path) -> None:
        log = AuditLog(audit_path)
        await _write_entries(log, count=1)
        lines = audit_path.read_text(encoding="utf-8").splitlines()
        header = json.loads(lines[0])
        header["version"] = 2
        lines[0] = json.dumps(header, sort_keys=True, separators=(",", ":"))
        audit_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        with pytest.raises(AuditIntegrityError, match="header schema"):
            AuditLog(audit_path)

    @pytest.mark.asyncio
    async def test_validly_chained_duplicate_event_id_refuses_admission(
        self, audit_path: Path
    ) -> None:
        log = AuditLog(audit_path)
        await _write_entries(log, count=1)
        lines = audit_path.read_text(encoding="utf-8").splitlines()
        first = _entry_lines(audit_path)[0]
        duplicate = json.loads(first)
        previous_hash = hashlib.sha256(first.encode("utf-8")).hexdigest()
        duplicate["previous_event_hash"] = previous_hash
        duplicate["previous_hash"] = previous_hash
        lines.append(json.dumps(duplicate, separators=(",", ":")))
        audit_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        with pytest.raises(AuditIntegrityError, match="duplicate event ID"):
            AuditLog(audit_path)

    @pytest.mark.asyncio
    async def test_partial_pending_successor_is_reconstructed_at_startup(
        self, audit_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("shisad.core.audit.MAX_SEGMENT_BYTES", 1_200)
        log = AuditLog(audit_path)
        await _write_entries(log, count=2)
        header = json.loads(audit_path.read_text(encoding="utf-8").splitlines()[0])
        archive = audit_path.with_name(f"audit.{int(header['sequence']):020d}.jsonl")
        os.replace(audit_path, archive)
        pending = audit_path.with_name(f".{audit_path.name}.next")
        pending.write_bytes(b'{"record_type":"shisad.audit.segment"')

        inspected = AuditLog(audit_path, _read_only=True)
        assert inspected.lifecycle_status["state"] == "recovery_pending"
        assert inspected.lifecycle_status["verified"] is False
        assert pending.exists()

        restarted = AuditLog(audit_path)
        assert restarted.verify_chain()[0] is True
        assert audit_path.exists()
        assert not pending.exists()

    @pytest.mark.asyncio
    async def test_retention_delete_failure_preserves_archive_and_degrades(
        self, audit_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("shisad.core.audit.MAX_SEGMENT_BYTES", 1_200)
        monkeypatch.setattr("shisad.core.audit.MAX_ARCHIVES", 1)
        original_unlink = Path.unlink

        def refuse_archive_unlink(path: Path, *args: object, **kwargs: object) -> None:
            if path.name.startswith("audit.") and path.suffix == ".jsonl":
                raise OSError("retention denied")
            original_unlink(path, *args, **kwargs)

        log = AuditLog(audit_path)
        monkeypatch.setattr(Path, "unlink", refuse_archive_unlink)
        await _write_entries(log, count=4)

        status = log.lifecycle_status
        assert status["state"] == "retention_degraded"
        assert status["reason_code"] == "audit.retention_delete_failed"
        assert len(list(audit_path.parent.glob("audit.*.jsonl"))) > 1
        assert log.verify_chain()[0] is True

        inspected = AuditLog(audit_path, _read_only=True)
        assert inspected.lifecycle_status["state"] == "retention_degraded"
        assert inspected.lifecycle_status["reason_code"] == "audit.retention_delete_failed"

    @pytest.mark.asyncio
    async def test_append_does_not_rescan_unchanged_retained_history(
        self, audit_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("shisad.core.audit.MAX_SEGMENT_BYTES", 1_200)
        log = AuditLog(audit_path)
        await _write_entries(log, count=1)

        def forbid_rescan() -> NoReturn:
            raise AssertionError("retained history rescanned")

        monkeypatch.setattr(log._segments, "_verify_all", forbid_rescan)
        await _write_entries(log, count=3)
        assert log.entry_count == 4

    @pytest.mark.asyncio
    async def test_post_admission_tamper_refuses_query(self, audit_path: Path) -> None:
        log = AuditLog(audit_path)
        await _write_entries(log, count=1)
        lines = audit_path.read_text(encoding="utf-8").splitlines()
        entry_index = next(
            index
            for index, line in enumerate(lines)
            if json.loads(line).get("record_type") != "shisad.audit.segment"
        )
        entry = json.loads(lines[entry_index])
        entry["data"]["tampered"] = True
        lines[entry_index] = json.dumps(entry, separators=(",", ":"))
        audit_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        with pytest.raises(AuditIntegrityError, match="data hash mismatch"):
            log.query()

    @pytest.mark.asyncio
    async def test_post_admission_tamper_refuses_next_append(self, audit_path: Path) -> None:
        log = AuditLog(audit_path)
        await _write_entries(log, count=1)
        lines = audit_path.read_text(encoding="utf-8").splitlines()
        entry_index = next(
            index
            for index, line in enumerate(lines)
            if json.loads(line).get("record_type") != "shisad.audit.segment"
        )
        entry = json.loads(lines[entry_index])
        entry["data"]["tampered"] = True
        lines[entry_index] = json.dumps(entry, separators=(",", ":"))
        audit_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        with pytest.raises(AuditIntegrityError, match="data hash mismatch"):
            await _write_entries(log, count=1)
        assert log.lifecycle_status["state"] == "unavailable"

    @pytest.mark.asyncio
    async def test_append_failure_latches_unavailable_and_requests_shutdown(
        self, audit_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        shutdown_requested = False

        def request_shutdown() -> None:
            nonlocal shutdown_requested
            shutdown_requested = True

        log = AuditLog(audit_path, on_unavailable=request_shutdown)

        def fail_append(_payload: str, _terminal_hash: str) -> None:
            raise OSError("disk full detail must not leak")

        monkeypatch.setattr(log._segments, "append", fail_append)
        with pytest.raises(OSError):
            await _write_entries(log, count=1)
        assert shutdown_requested is True
        assert log.lifecycle_status["state"] == "unavailable"
        assert log.lifecycle_status["reason_code"] == "audit.append_failed"

        with pytest.raises(AuditUnavailableError, match=r"audit\.append_failed"):
            await _write_entries(log, count=1)

    @pytest.mark.asyncio
    async def test_short_append_is_not_completed_as_multiple_writes(
        self, audit_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        log = AuditLog(audit_path)
        await _write_entries(log, count=1)
        real_write = os.write
        shortened = False

        def short_once(descriptor: int, payload: bytes) -> int:
            nonlocal shortened
            if not shortened and len(payload) > 1:
                shortened = True
                return real_write(descriptor, payload[:-1])
            return real_write(descriptor, payload)

        monkeypatch.setattr("shisad.core.audit_segments.os.write", short_once)
        with pytest.raises(OSError, match="short audit write"):
            await _write_entries(log, count=1)
        assert log.lifecycle_status["state"] == "unavailable"

    @pytest.mark.asyncio
    async def test_oversize_row_is_rejected_before_write(
        self, audit_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("shisad.core.audit.MAX_SEGMENT_BYTES", 512)
        log = AuditLog(audit_path)
        with pytest.raises(AuditUnavailableError, match=r"audit\.row_oversize"):
            await log.persist(
                ToolRejected(
                    session_id=SessionId("oversize"),
                    actor="test",
                    tool_name=ToolName("shell.exec"),
                    reason="x" * 2_000,
                )
            )
        assert not audit_path.exists()


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
