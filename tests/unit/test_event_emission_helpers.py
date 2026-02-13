"""Unit checks for shared handler helper functions."""

from __future__ import annotations

import pytest

from shisad.core.api.schema import SessionCreateParams
from shisad.core.events import SessionCreated
from shisad.daemon.context import RequestContext
from shisad.daemon.handlers._helpers import build_params_payload, publish_event


class _StubEventBus:
    def __init__(self) -> None:
        self.events: list[object] = []

    async def publish(self, event: object) -> None:
        self.events.append(event)


@pytest.mark.asyncio
async def test_publish_event_delegates_to_event_bus() -> None:
    bus = _StubEventBus()
    event = SessionCreated(
        session_id="s1",
        user_id="alice",
        workspace_id="ws1",
        actor="unit",
    )
    await publish_event(bus, event)  # type: ignore[arg-type]
    assert bus.events == [event]


def test_build_params_payload_carries_internal_context_fields() -> None:
    marker = object()
    payload = build_params_payload(
        SessionCreateParams(channel="matrix", user_id="alice", workspace_id="w1"),
        RequestContext(
            rpc_peer={"uid": 1, "gid": 2, "pid": 3},
            is_internal_ingress=True,
            trust_level_override="trusted",
        ),
        internal_ingress_marker=marker,
    )
    assert payload["_rpc_peer"] == {"uid": 1, "gid": 2, "pid": 3}
    assert payload["_internal_ingress_marker"] is marker
    assert payload["trust_level"] == "trusted"
