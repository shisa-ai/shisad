"""Audit query filtering and since parsing."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from shisad.core.audit import AuditLog
from shisad.core.events import SessionCreated
from shisad.core.types import SessionId, UserId


@pytest.mark.asyncio
async def test_audit_query_filters_actor_and_since(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "audit.jsonl")
    now = datetime.now(UTC)
    await log.persist(
        SessionCreated(
            session_id=SessionId("s-older"),
            user_id=UserId("u1"),
            actor="uid:1000",
            timestamp=now - timedelta(hours=2),
        )
    )
    await log.persist(
        SessionCreated(
            session_id=SessionId("s-newer"),
            user_id=UserId("u2"),
            actor="uid:2000",
            timestamp=now,
        )
    )

    since = AuditLog.parse_since("1h", now=now)
    results = log.query(since=since, actor="uid:2000")
    assert len(results) == 1
    assert results[0]["session_id"] == "s-newer"
    assert results[0]["actor"] == "uid:2000"


def test_parse_since_supports_iso_and_relative_formats() -> None:
    fixed_now = datetime(2026, 2, 9, 12, 0, tzinfo=UTC)

    rel = AuditLog.parse_since("30m", now=fixed_now)
    assert rel == fixed_now - timedelta(minutes=30)

    iso = AuditLog.parse_since("2026-02-08T12:00:00Z", now=fixed_now)
    assert iso == datetime(2026, 2, 8, 12, 0, tzinfo=UTC)

    date_only = AuditLog.parse_since("2026-02-08", now=fixed_now)
    assert date_only == datetime(2026, 2, 8, 0, 0, tzinfo=UTC)

    with pytest.raises(ValueError):
        AuditLog.parse_since("not-a-time", now=fixed_now)
