"""Audit/dashboard handler implementations."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, cast

from shisad.core.audit import AuditLog
from shisad.daemon.handlers._mixin_typing import HandlerMixinBase
from shisad.ui.dashboard import DashboardQuery


class DashboardImplMixin(HandlerMixinBase):
    async def do_audit_query(self, params: Mapping[str, Any]) -> dict[str, Any]:
        since = AuditLog.parse_since(params.get("since"))
        results = self._audit_log.query(
            since=since,
            event_type=params.get("event_type"),
            session_id=params.get("session_id"),
            actor=params.get("actor"),
            limit=int(params.get("limit", 100)),
        )
        return {"events": results, "total": len(results)}

    async def do_dashboard_audit_explorer(self, params: Mapping[str, Any]) -> dict[str, Any]:
        since = AuditLog.parse_since(params.get("since"))
        query = DashboardQuery(
            since=since,
            event_type=str(params.get("event_type") or "").strip() or None,
            session_id=str(params.get("session_id") or "").strip() or None,
            actor=str(params.get("actor") or "").strip() or None,
            text_search=str(params.get("text_search") or ""),
            limit=max(1, int(params.get("limit", 100))),
        )
        payload = self._dashboard.audit_explorer(query)
        valid, checked, error = self._audit_log.verify_chain()
        payload["hash_chain"] = {
            "valid": valid,
            "entries_checked": checked,
            "error": error,
        }
        return cast(dict[str, Any], payload)

    async def do_dashboard_egress_review(self, params: Mapping[str, Any]) -> dict[str, Any]:
        limit = max(1, int(params.get("limit", 200)))
        return cast(dict[str, Any], self._dashboard.blocked_or_flagged_egress(limit=limit))

    async def do_dashboard_skill_provenance(self, params: Mapping[str, Any]) -> dict[str, Any]:
        limit = max(1, int(params.get("limit", 200)))
        payload = self._dashboard.skill_provenance(limit=limit)
        installed = [item.model_dump(mode="json") for item in self._skill_manager.list_installed()]
        timeline: dict[str, dict[str, Any]] = {}
        for row in payload.get("events", []):
            if not isinstance(row, dict):
                continue
            data = row.get("data", {})
            if not isinstance(data, dict):
                continue
            skill_name = str(data.get("skill_name") or data.get("name") or "").strip()
            if not skill_name:
                continue
            bucket = timeline.setdefault(
                skill_name,
                {"skill_name": skill_name, "versions": [], "events": []},
            )
            version = str(data.get("version") or "").strip()
            if version and version not in bucket["versions"]:
                bucket["versions"].append(version)
            bucket["events"].append(
                {
                    "event_type": row.get("event_type"),
                    "timestamp": row.get("timestamp"),
                    "signature_status": data.get("signature_status", ""),
                    "capabilities": data.get("capabilities", {}),
                    "status": data.get("status", ""),
                }
            )
        payload["installed"] = installed
        payload["timeline"] = sorted(timeline.values(), key=lambda item: item["skill_name"])
        return cast(dict[str, Any], payload)

    async def do_dashboard_alerts(self, params: Mapping[str, Any]) -> dict[str, Any]:
        limit = max(1, int(params.get("limit", 200)))
        return cast(dict[str, Any], self._dashboard.alerts(limit=limit))

    async def do_dashboard_mark_false_positive(self, params: Mapping[str, Any]) -> dict[str, Any]:
        event_id = str(params.get("event_id", "")).strip()
        if not event_id:
            raise ValueError("event_id is required")
        reason = str(params.get("reason", "false_positive")).strip() or "false_positive"
        self._dashboard.mark_false_positive(event_id=event_id, reason=reason)
        return {"marked": True, "event_id": event_id, "reason": reason}
