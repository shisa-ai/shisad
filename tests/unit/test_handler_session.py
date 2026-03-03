"""Unit checks for session handler wrappers."""

from __future__ import annotations

import pytest

from shisad.core.api.schema import (
    NoParams,
    SessionCreateParams,
    SessionGrantCapabilitiesParams,
    SessionSetModeParams,
    SessionTerminateParams,
)
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

    async def do_session_set_mode(self, payload: dict[str, object]) -> dict[str, object]:
        self.payloads.append(("set_mode", payload))
        return {
            "session_id": str(payload.get("session_id", "")),
            "mode": "admin_cleanroom",
            "changed": True,
        }

    async def do_session_grant_capabilities(self, payload: dict[str, object]) -> dict[str, object]:
        self.payloads.append(("grant", payload))
        return {
            "session_id": str(payload.get("session_id", "")),
            "granted": True,
            "capabilities": list(payload.get("capabilities", [])),
        }

    async def do_session_terminate(self, payload: dict[str, object]) -> dict[str, object]:
        self.payloads.append(("terminate", payload))
        return {
            "session_id": str(payload.get("session_id", "")),
            "terminated": True,
        }


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


@pytest.mark.asyncio
async def test_session_set_mode_uses_request_context_payload() -> None:
    marker = object()
    impl = _StubImpl()
    handlers = SessionHandlers(impl, internal_ingress_marker=marker)  # type: ignore[arg-type]

    result = await handlers.handle_session_set_mode(
        SessionSetModeParams(session_id="sess-1", mode="admin_cleanroom"),
        RequestContext(rpc_peer={"uid": 1000, "gid": 1000, "pid": 1}),
    )

    assert result.changed is True
    payload = impl.payloads[-1][1]
    assert payload["session_id"] == "sess-1"
    assert payload["mode"] == "admin_cleanroom"
    assert payload["_rpc_peer"] == {"uid": 1000, "gid": 1000, "pid": 1}


@pytest.mark.asyncio
async def test_session_grant_capabilities_uses_request_context_payload() -> None:
    impl = _StubImpl()
    handlers = SessionHandlers(impl, internal_ingress_marker=object())  # type: ignore[arg-type]

    result = await handlers.handle_session_grant_capabilities(
        SessionGrantCapabilitiesParams(
            session_id="sess-1",
            capabilities=["http.request"],
            reason="manual",
        ),
        RequestContext(rpc_peer={"uid": 1000, "gid": 1000, "pid": 1}),
    )

    assert result.granted is True
    payload = impl.payloads[-1][1]
    assert payload["session_id"] == "sess-1"
    assert payload["capabilities"] == ["http.request"]
    assert payload["reason"] == "manual"


@pytest.mark.asyncio
async def test_session_terminate_uses_request_context_payload() -> None:
    marker = object()
    impl = _StubImpl()
    handlers = SessionHandlers(impl, internal_ingress_marker=marker)  # type: ignore[arg-type]

    result = await handlers.handle_session_terminate(
        SessionTerminateParams(session_id="sess-1"),
        RequestContext(
            rpc_peer={"uid": 1000, "gid": 1000, "pid": 1},
            is_internal_ingress=False,
        ),
    )

    assert result.terminated is True
    payload = impl.payloads[-1][1]
    assert payload["session_id"] == "sess-1"
    assert payload["_rpc_peer"] == {"uid": 1000, "gid": 1000, "pid": 1}
