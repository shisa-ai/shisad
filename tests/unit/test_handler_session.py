"""Unit checks for session handler wrappers."""

from __future__ import annotations

import pytest

from shisad.core.api.schema import NoParams, SessionCreateParams
from shisad.daemon.context import RequestContext
from shisad.daemon.handlers.session import SessionHandlers


class _StubImpl:
    def __init__(self) -> None:
        self.payloads: list[tuple[str, dict[str, object]]] = []

    async def do_session_create(self, payload: dict[str, object]) -> dict[str, object]:
        self.payloads.append(("create", payload))
        return {"session_id": "sess-1"}

    async def do_session_list(self, payload: dict[str, object]) -> dict[str, object]:
        self.payloads.append(("list", payload))
        return {"sessions": []}


@pytest.mark.asyncio
async def test_session_create_uses_request_context_payload() -> None:
    marker = object()
    impl = _StubImpl()
    handlers = SessionHandlers(impl, internal_ingress_marker=marker)  # type: ignore[arg-type]

    result = await handlers.handle_session_create(
        SessionCreateParams(channel="matrix", user_id="alice", workspace_id="w1"),
        RequestContext(
            rpc_peer={"uid": 1000, "gid": 1000, "pid": 1},
            is_internal_ingress=True,
            trust_level_override="trusted",
        ),
    )

    assert result.session_id == "sess-1"
    payload = impl.payloads[0][1]
    assert payload["channel"] == "matrix"
    assert payload["_rpc_peer"] == {"uid": 1000, "gid": 1000, "pid": 1}
    assert payload["_internal_ingress_marker"] is marker
    assert payload["trust_level"] == "trusted"


@pytest.mark.asyncio
async def test_session_list_passes_empty_payload() -> None:
    impl = _StubImpl()
    handlers = SessionHandlers(impl, internal_ingress_marker=object())  # type: ignore[arg-type]

    result = await handlers.handle_session_list(NoParams(), RequestContext())

    assert result.sessions == []
    assert impl.payloads == [("list", {})]
