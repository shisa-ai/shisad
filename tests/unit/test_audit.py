"""M0.T6-T8: Audit log hash-chain detects insertion, modification, deletion."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from shisad.core.audit import AuditLog
from shisad.core.events import SessionCreated
from shisad.core.types import SessionId, UserId


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
