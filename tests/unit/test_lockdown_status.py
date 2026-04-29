"""Regression checks for lockdown status inspection semantics."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from shisad.core.types import SessionId
from shisad.daemon.handlers._impl_admin import AdminImplMixin
from shisad.security.lockdown import LockdownLevel, LockdownManager


class _StatusHarness(AdminImplMixin):
    def __init__(self, *, active_sessions: list[object] | None = None) -> None:
        self._lockdown_manager = LockdownManager()
        self._session_manager = SimpleNamespace(
            list_active=lambda: list(active_sessions or [])
        )


@pytest.mark.asyncio
async def test_lockdown_status_all_omits_stale_default_rows() -> None:
    harness = _StatusHarness()
    stale_sid = SessionId("stale-default")
    explicit_sid = SessionId("stale-explicit")

    harness._lockdown_manager.state_for(stale_sid)
    harness._lockdown_manager.set_level(
        explicit_sid,
        level=LockdownLevel.QUARANTINE,
        reason="incident",
    )

    status = await harness.do_lockdown_status({"all": True})

    session_ids = {row["session_id"] for row in status["statuses"]}
    assert stale_sid not in session_ids
    assert explicit_sid in session_ids
    explicit_row = next(
        row for row in status["statuses"] if row["session_id"] == explicit_sid
    )
    assert explicit_row["active"] is False
    assert explicit_row["level"] == "quarantine"
    assert explicit_row["mode"] == ""
    assert explicit_row["updated_at"] is not None
