"""Branch-level regression tests for structured-tool paths in _impl."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from shisad.core.events import ToolApproved, ToolExecuted, ToolRejected
from shisad.core.session import Session, SessionManager
from shisad.core.types import SessionId, TaintLabel, ToolName, UserId, WorkspaceId
from shisad.daemon.handlers._impl import HandlerImplementation
from shisad.security.control_plane.schema import Origin


class _EventCollector:
    def __init__(self) -> None:
        self.events: list[object] = []

    async def publish(self, event: object) -> None:
        self.events.append(event)


class _ExecutionRecorder:
    def __init__(self) -> None:
        self.results: list[bool] = []

    def record_execution(self, *, action: object, success: bool) -> None:
        _ = action
        self.results.append(success)


class _NoopRateLimiter:
    def consume(self, *, session_id: str, user_id: str, tool_name: str) -> None:
        _ = (session_id, user_id, tool_name)


class _WebToolkitStub:
    def __init__(self, payload: dict[str, Any]) -> None:
        self._payload = payload
        self.calls: list[tuple[str, int]] = []

    def search(self, *, query: str, limit: int) -> dict[str, Any]:
        self.calls.append((query, limit))
        return dict(self._payload)


class _FsGitToolkitStub:
    def __init__(self, payload: dict[str, Any]) -> None:
        self._payload = payload
        self.calls: list[str] = []

    def git_status(self, *, repo_path: str) -> dict[str, Any]:
        self.calls.append(repo_path)
        return dict(self._payload)


class _StructuredBranchHarness:
    def __init__(self, *, web_payload: dict[str, Any], git_status_payload: dict[str, Any]) -> None:
        self._session_manager = SessionManager()
        self._session = self._session_manager.create(
            channel="cli",
            user_id=UserId("user-1"),
            workspace_id=WorkspaceId("ws-1"),
            metadata={"trust_level": "trusted"},
        )
        self._config = SimpleNamespace(checkpoint_trigger="never")
        self._rate_limiter = _NoopRateLimiter()
        self._registry = SimpleNamespace(get_tool=lambda _tool_name: None)
        self._event_bus = _EventCollector()
        self._control_plane = _ExecutionRecorder()
        self._web_toolkit = _WebToolkitStub(web_payload)
        self._fs_git_toolkit = _FsGitToolkitStub(git_status_payload)

    @property
    def session_id(self) -> SessionId:
        return self._session.id

    def _origin_for(
        self,
        *,
        session: Session,
        actor: str,
        skill_name: str = "",
        task_id: str = "",
    ) -> Origin:
        return Origin(
            session_id=str(session.id),
            user_id=str(session.user_id),
            workspace_id=str(session.workspace_id),
            actor=actor,
            channel=str(session.channel),
            trust_level=str(session.metadata.get("trust_level", "untrusted")),
            skill_name=skill_name,
            task_id=task_id,
        )

    @staticmethod
    def _sanitize_tool_output_text(raw: str) -> str:
        return raw


@pytest.mark.asyncio
async def test_m7_impl_web_search_branch_records_success_with_structured_helper() -> None:
    harness = _StructuredBranchHarness(
        web_payload={"ok": True, "results": [{"title": "roadmap"}]},
        git_status_payload={"ok": True, "status": "clean"},
    )
    success, checkpoint_id, output = await HandlerImplementation._execute_approved_action(
        harness,  # type: ignore[arg-type]
        sid=harness.session_id,
        user_id=UserId("user-1"),
        tool_name=ToolName("web_search"),
        arguments={"query": "roadmap", "limit": 2},
        capabilities=set(),
        approval_actor="control_api",
    )

    assert success is True
    assert checkpoint_id is None
    assert output is not None
    assert output.tool_name == "web_search"
    assert output.taint_labels == {TaintLabel.UNTRUSTED}
    assert harness._web_toolkit.calls == [("roadmap", 2)]
    assert harness._control_plane.results == [True]
    assert any(isinstance(event, ToolApproved) for event in harness._event_bus.events)
    assert any(
        isinstance(event, ToolExecuted) and event.success
        for event in harness._event_bus.events
    )
    assert not any(isinstance(event, ToolRejected) for event in harness._event_bus.events)


@pytest.mark.asyncio
async def test_m7_impl_git_status_branch_failure_keeps_rejected_before_executed() -> None:
    harness = _StructuredBranchHarness(
        web_payload={"ok": True, "results": []},
        git_status_payload={"ok": False, "error": "git_status_failed"},
    )
    success, checkpoint_id, output = await HandlerImplementation._execute_approved_action(
        harness,  # type: ignore[arg-type]
        sid=harness.session_id,
        user_id=UserId("user-1"),
        tool_name=ToolName("git.status"),
        arguments={"repo_path": "/tmp/repo"},
        capabilities=set(),
        approval_actor="control_api",
    )

    assert success is False
    assert checkpoint_id is None
    assert output is not None
    assert output.tool_name == "git.status"
    assert output.taint_labels == set()
    assert harness._fs_git_toolkit.calls == ["/tmp/repo"]
    assert harness._control_plane.results == [False]

    rejected_indices = [
        index
        for index, event in enumerate(harness._event_bus.events)
        if isinstance(event, ToolRejected)
    ]
    executed_indices = [
        index
        for index, event in enumerate(harness._event_bus.events)
        if isinstance(event, ToolExecuted)
    ]
    assert rejected_indices
    assert executed_indices
    assert rejected_indices[0] < executed_indices[0]
