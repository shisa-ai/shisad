"""RequestContext and typed handler interface checks."""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest
from pydantic import BaseModel

from shisad.core.interfaces import TypedHandler
from shisad.daemon.context import RequestContext
from shisad.security.firewall import FirewallResult


class _DummyParams(BaseModel):
    value: str


class _DummyHandler:
    async def __call__(self, params: BaseModel, ctx: RequestContext) -> BaseModel:
        _ = ctx
        return params


def test_request_context_defaults() -> None:
    ctx = RequestContext()
    assert ctx.rpc_peer is None
    assert ctx.is_internal_ingress is False
    assert ctx.trust_level_override is None
    assert ctx.firewall_result is None


def test_request_context_is_frozen() -> None:
    ctx = RequestContext(rpc_peer={"uid": 1000, "gid": 1000, "pid": 123})
    with pytest.raises(FrozenInstanceError):
        ctx.rpc_peer = {"uid": 1, "gid": 1, "pid": 1}  # type: ignore[misc]


def test_request_context_accepts_firewall_result() -> None:
    result = FirewallResult(
        sanitized_text="safe text",
        original_hash="abc123",
        risk_score=0.5,
    )
    ctx = RequestContext(firewall_result=result)
    assert ctx.firewall_result is not None
    assert ctx.firewall_result.risk_score == 0.5


def test_typed_handler_protocol_conformance() -> None:
    assert isinstance(_DummyHandler(), TypedHandler)
