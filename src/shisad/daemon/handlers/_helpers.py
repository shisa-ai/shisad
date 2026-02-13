"""Shared helpers for typed daemon handler modules."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel

from shisad.core.events import BaseEvent, EventBus
from shisad.daemon.context import RequestContext


def build_params_payload(
    params: BaseModel,
    ctx: RequestContext,
    *,
    internal_ingress_marker: object,
) -> dict[str, Any]:
    payload = params.model_dump(mode="json", exclude_unset=True)
    if ctx.rpc_peer is not None:
        payload["_rpc_peer"] = dict(ctx.rpc_peer)
    if ctx.is_internal_ingress:
        payload["_internal_ingress_marker"] = internal_ingress_marker
    if ctx.trust_level_override is not None:
        payload["trust_level"] = ctx.trust_level_override
    if ctx.firewall_result is not None:
        payload["_firewall_result"] = ctx.firewall_result.model_dump(mode="json")
    return payload


async def publish_event(event_bus: EventBus, event: BaseEvent) -> None:
    await event_bus.publish(event)
