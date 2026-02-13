"""Unit checks for dashboard handler wrappers."""

from __future__ import annotations

import pytest

from shisad.core.api.schema import (
    AuditQueryParams,
    DashboardMarkFalsePositiveParams,
    DashboardQueryParams,
)
from shisad.daemon.context import RequestContext
from shisad.daemon.handlers.dashboard import DashboardHandlers


class _StubImpl:
    async def do_audit_query(self, _payload: dict[str, object]) -> dict[str, object]:
        return {"events": [{"event_type": "x"}], "total": 1}

    async def do_dashboard_audit_explorer(self, _payload: dict[str, object]) -> dict[str, object]:
        return {"events": [], "count": 0}

    async def do_dashboard_egress_review(self, _payload: dict[str, object]) -> dict[str, object]:
        return {"events": [], "count": 0}

    async def do_dashboard_skill_provenance(
        self, _payload: dict[str, object]
    ) -> dict[str, object]:
        return {"events": [], "count": 0}

    async def do_dashboard_alerts(self, _payload: dict[str, object]) -> dict[str, object]:
        return {"alerts": [], "count": 0}

    async def do_dashboard_mark_false_positive(
        self, payload: dict[str, object]
    ) -> dict[str, object]:
        return {"marked": True, "event_id": str(payload["event_id"]), "reason": "manual"}


@pytest.mark.asyncio
async def test_dashboard_query_wrappers() -> None:
    handlers = DashboardHandlers(_StubImpl(), internal_ingress_marker=object())  # type: ignore[arg-type]
    audit = await handlers.handle_audit_query(AuditQueryParams(limit=5), RequestContext())
    alerts = await handlers.handle_dashboard_alerts(DashboardQueryParams(limit=5), RequestContext())
    assert audit.total == 1
    assert alerts.model_dump(mode="json")["count"] == 0


@pytest.mark.asyncio
async def test_dashboard_mark_false_positive_wrapper() -> None:
    handlers = DashboardHandlers(_StubImpl(), internal_ingress_marker=object())  # type: ignore[arg-type]
    result = await handlers.handle_dashboard_mark_false_positive(
        DashboardMarkFalsePositiveParams(event_id="evt-1"),
        RequestContext(),
    )
    assert result.marked is True
