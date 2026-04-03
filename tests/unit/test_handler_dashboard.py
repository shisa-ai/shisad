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
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, object]]] = []

    async def do_audit_query(self, _payload: dict[str, object]) -> dict[str, object]:
        self.calls.append(("audit", _payload))
        return {"events": [{"event_type": "x"}], "total": 1}

    async def do_dashboard_audit_explorer(self, _payload: dict[str, object]) -> dict[str, object]:
        self.calls.append(("audit_explorer", _payload))
        return {"events": [], "count": 0}

    async def do_dashboard_egress_review(self, _payload: dict[str, object]) -> dict[str, object]:
        self.calls.append(("egress_review", _payload))
        return {"events": [], "count": 0}

    async def do_dashboard_skill_provenance(self, _payload: dict[str, object]) -> dict[str, object]:
        self.calls.append(("skill_provenance", _payload))
        return {"events": [], "count": 0}

    async def do_dashboard_alerts(self, _payload: dict[str, object]) -> dict[str, object]:
        self.calls.append(("alerts", _payload))
        return {"alerts": [], "count": 0}

    async def do_dashboard_mark_false_positive(
        self, payload: dict[str, object]
    ) -> dict[str, object]:
        self.calls.append(("mark_false_positive", payload))
        return {"marked": True, "event_id": str(payload["event_id"]), "reason": "manual"}


@pytest.mark.asyncio
async def test_dashboard_query_wrappers() -> None:
    stub = _StubImpl()
    handlers = DashboardHandlers(stub, internal_ingress_marker=object())  # type: ignore[arg-type]
    audit = await handlers.handle_audit_query(AuditQueryParams(limit=5), RequestContext())
    explorer = await handlers.handle_dashboard_audit_explorer(
        DashboardQueryParams(limit=5),
        RequestContext(),
    )
    egress = await handlers.handle_dashboard_egress_review(
        DashboardQueryParams(limit=5),
        RequestContext(),
    )
    provenance = await handlers.handle_dashboard_skill_provenance(
        DashboardQueryParams(limit=5),
        RequestContext(),
    )
    alerts = await handlers.handle_dashboard_alerts(DashboardQueryParams(limit=5), RequestContext())
    assert audit.total == 1
    assert explorer.count == 0
    assert egress.count == 0
    assert provenance.count == 0
    assert alerts.model_dump(mode="json")["count"] == 0
    assert [name for name, _ in stub.calls] == [
        "audit",
        "audit_explorer",
        "egress_review",
        "skill_provenance",
        "alerts",
    ]


@pytest.mark.asyncio
async def test_dashboard_mark_false_positive_wrapper() -> None:
    stub = _StubImpl()
    handlers = DashboardHandlers(stub, internal_ingress_marker=object())  # type: ignore[arg-type]
    result = await handlers.handle_dashboard_mark_false_positive(
        DashboardMarkFalsePositiveParams(event_id="evt-1"),
        RequestContext(),
    )
    assert result.marked is True
    assert stub.calls[0][0] == "mark_false_positive"
