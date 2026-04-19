"""M7.3 runtime wiring checks for msgvault email tools."""

from __future__ import annotations

from typing import Any

from shisad.core.events import EventBus
from shisad.core.session import Session
from shisad.core.types import (
    Capability,
    PEPDecisionKind,
    SessionId,
    SessionMode,
    ToolName,
    UserId,
    WorkspaceId,
)
from shisad.daemon.handlers._impl import (
    HandlerImplementation,
    StructuredToolContext,
    _structured_email_read,
    _structured_email_search,
)
from shisad.daemon.services import _build_tool_registry
from shisad.security.pep import PEP, PolicyContext
from shisad.security.policy import PolicyBundle


class _RecordingEmailToolkit:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def search(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("search", dict(kwargs)))
        return {"ok": True, "results": [], "taint_labels": ["untrusted", "email"]}

    def read_message(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("read_message", dict(kwargs)))
        return {"ok": True, "message": {}, "taint_labels": ["untrusted", "email"]}


def _context() -> StructuredToolContext:
    return StructuredToolContext(
        session_id=SessionId("s-email"),
        user_id=UserId("u-email"),
        workspace_id=WorkspaceId("w-email"),
        session=Session(
            id=SessionId("s-email"),
            channel="cli",
            user_id=UserId("u-email"),
            workspace_id=WorkspaceId("w-email"),
            mode=SessionMode.DEFAULT,
        ),
    )


def test_tool_registry_registers_read_only_email_tools() -> None:
    registry, _alarm = _build_tool_registry(EventBus())

    search = registry.get_tool(ToolName("email.search"))
    read = registry.get_tool(ToolName("email.read"))
    assert search is not None
    assert read is not None
    assert set(search.capabilities_required) == {Capability.EMAIL_READ}
    assert set(read.capabilities_required) == {Capability.EMAIL_READ}
    assert {param.name for param in read.parameters} == {"message_id", "account"}
    assert search.require_confirmation is False
    assert read.require_confirmation is False
    assert registry.get_tool(ToolName("email.send")) is None
    assert registry.get_tool(ToolName("email.write")) is None
    assert registry.get_tool(ToolName("calendar.create")) is None


def test_email_tools_require_email_read_capability() -> None:
    registry, _alarm = _build_tool_registry(EventBus())
    pep = PEP(PolicyBundle(default_require_confirmation=False), registry)

    rejected = pep.evaluate(
        ToolName("email.search"),
        {"query": "invoice"},
        PolicyContext(capabilities={Capability.MESSAGE_READ}),
    )
    allowed = pep.evaluate(
        ToolName("email.search"),
        {"query": "invoice"},
        PolicyContext(capabilities={Capability.EMAIL_READ}),
    )

    assert rejected.kind == PEPDecisionKind.REJECT
    assert allowed.kind == PEPDecisionKind.ALLOW


def test_structured_tool_registry_includes_email_handlers() -> None:
    registry = HandlerImplementation._structured_tool_registry()  # type: ignore[attr-defined]

    assert "email.search" in registry
    assert "email.read" in registry


def test_structured_email_search_passes_bounded_arguments() -> None:
    toolkit = _RecordingEmailToolkit()
    handler = type("_Handler", (), {"_msgvault_toolkit": toolkit})()

    payload = _structured_email_search(
        handler,
        {
            "query": "from:alice@example.com",
            "limit": "4",
            "offset": "2",
            "account": "me@example.com",
        },
        _context(),
    )

    assert payload["ok"] is True
    assert toolkit.calls == [
        (
            "search",
            {
                "query": "from:alice@example.com",
                "limit": 4,
                "offset": 2,
                "account": "me@example.com",
            },
        )
    ]


def test_structured_email_read_requires_message_id() -> None:
    toolkit = _RecordingEmailToolkit()
    handler = type("_Handler", (), {"_msgvault_toolkit": toolkit})()

    missing = _structured_email_read(handler, {}, _context())
    found = _structured_email_read(
        handler,
        {"message_id": "msg-101", "account": "me@example.com"},
        _context(),
    )

    assert missing == {
        "ok": False,
        "error": "email_message_id_required",
        "taint_labels": ["untrusted", "email"],
    }
    assert found["ok"] is True
    assert toolkit.calls == [
        ("read_message", {"message_id": "msg-101", "account": "me@example.com"})
    ]
