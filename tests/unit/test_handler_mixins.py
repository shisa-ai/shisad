"""Coverage-focused smoke tests for small daemon handler modules.

These modules are thin adapters over toolkits/managers, but they are still part of
the runtime security surface (they parse params and dispatch). CI enforces a per
module coverage floor, so we keep basic execution coverage here.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from shisad.core.api.schema import (
    FsListParams,
    FsReadParams,
    FsWriteParams,
    GitDiffParams,
    GitLogParams,
    GitStatusParams,
    RealityCheckReadParams,
    RealityCheckSearchParams,
    WebFetchParams,
    WebSearchParams,
)
from shisad.core.events import SkillInstalled, SkillProfiled, SkillReviewRequested, SkillRevoked
from shisad.daemon.context import RequestContext
from shisad.daemon.handlers._impl_assistant import AssistantImplMixin
from shisad.daemon.handlers._impl_dashboard import DashboardImplMixin
from shisad.daemon.handlers._impl_skills import SkillsImplMixin
from shisad.daemon.handlers.assistant import AssistantHandlers


@pytest.mark.asyncio
async def test_assistant_impl_mixin_smoke() -> None:
    class DummyWebToolkit:
        def search(self, *, query: str, limit: int) -> dict[str, Any]:
            return {"ok": True, "query": query, "limit": limit}

        def fetch(self, *, url: str, snapshot: bool, max_bytes: int | None) -> dict[str, Any]:
            return {"ok": True, "url": url, "snapshot": snapshot, "max_bytes": max_bytes}

    class DummyRealitycheckToolkit:
        def search(self, *, query: str, limit: int, mode: str) -> dict[str, Any]:
            return {"ok": True, "query": query, "limit": limit, "mode": mode}

        def read_source(self, *, path: str, max_bytes: int | None) -> dict[str, Any]:
            return {"ok": True, "path": path, "max_bytes": max_bytes}

    class DummyFsGitToolkit:
        def list_dir(self, *, path: str, recursive: bool, limit: int) -> dict[str, Any]:
            return {"ok": True, "path": path, "recursive": recursive, "limit": limit}

        def read_file(self, *, path: str, max_bytes: int | None) -> dict[str, Any]:
            return {"ok": True, "path": path, "max_bytes": max_bytes}

        def write_file(self, *, path: str, content: str, confirm: bool) -> dict[str, Any]:
            return {"ok": True, "path": path, "content": content, "confirm": confirm}

        def git_status(self, *, repo_path: str) -> dict[str, Any]:
            return {"ok": True, "repo_path": repo_path}

        def git_diff(self, *, repo_path: str, ref: str, max_lines: int) -> dict[str, Any]:
            return {"ok": True, "repo_path": repo_path, "ref": ref, "max_lines": max_lines}

        def git_log(self, *, repo_path: str, limit: int) -> dict[str, Any]:
            return {"ok": True, "repo_path": repo_path, "limit": limit}

    class DummyAssistant(AssistantImplMixin):
        def __init__(self) -> None:
            self._web_toolkit = DummyWebToolkit()
            self._realitycheck_toolkit = DummyRealitycheckToolkit()
            self._fs_git_toolkit = DummyFsGitToolkit()

    impl = DummyAssistant()

    assert (await impl.do_web_search({"query": "q", "limit": 2}))["limit"] == 2
    assert (await impl.do_web_fetch({"url": "https://x", "snapshot": True, "max_bytes": "7"}))[
        "max_bytes"
    ] == 7
    assert (await impl.do_realitycheck_search({"query": "q", "limit": 1, "mode": "auto"}))[
        "mode"
    ] == "auto"
    assert (await impl.do_realitycheck_read({"path": "p", "max_bytes": 9}))["max_bytes"] == 9
    assert (await impl.do_fs_list({"path": ".", "recursive": False, "limit": 1}))["ok"] is True
    assert (await impl.do_fs_read({"path": "README.md"}))["path"] == "README.md"
    assert (await impl.do_fs_write({"path": "x", "content": "y", "confirm": True}))[
        "confirm"
    ] is True
    assert (await impl.do_git_status({"repo_path": "."}))["repo_path"] == "."
    assert (await impl.do_git_diff({"repo_path": ".", "ref": "HEAD", "max_lines": 10}))[
        "max_lines"
    ] == 10
    assert (await impl.do_git_log({"repo_path": ".", "limit": 3}))["limit"] == 3


@pytest.mark.asyncio
async def test_assistant_handlers_smoke() -> None:
    class DummyImpl:
        async def do_web_search(self, payload: dict[str, Any]) -> dict[str, Any]:
            assert payload["query"] == "hello"
            return {"ok": True}

        async def do_web_fetch(self, payload: dict[str, Any]) -> dict[str, Any]:
            assert payload["url"] == "https://example.com"
            return {"ok": True}

        async def do_realitycheck_search(self, payload: dict[str, Any]) -> dict[str, Any]:
            assert payload["query"] == "rc"
            return {"ok": True}

        async def do_realitycheck_read(self, payload: dict[str, Any]) -> dict[str, Any]:
            assert payload["path"] == "x"
            return {"ok": True}

        async def do_fs_list(self, payload: dict[str, Any]) -> dict[str, Any]:
            assert payload["path"] == "."
            return {"ok": True}

        async def do_fs_read(self, payload: dict[str, Any]) -> dict[str, Any]:
            assert payload["path"] == "README.md"
            return {"ok": True}

        async def do_fs_write(self, payload: dict[str, Any]) -> dict[str, Any]:
            assert payload["path"] == "x"
            return {"ok": True}

        async def do_git_status(self, payload: dict[str, Any]) -> dict[str, Any]:
            assert payload["repo_path"] == "."
            return {"ok": True}

        async def do_git_diff(self, payload: dict[str, Any]) -> dict[str, Any]:
            assert payload["ref"] == "HEAD"
            return {"ok": True}

        async def do_git_log(self, payload: dict[str, Any]) -> dict[str, Any]:
            assert payload["limit"] == 1
            return {"ok": True}

    ctx = RequestContext(is_internal_ingress=True)
    marker = object()
    handlers = AssistantHandlers(DummyImpl(), internal_ingress_marker=marker)

    assert (await handlers.handle_web_search(WebSearchParams(query="hello"), ctx)).ok is True
    assert (
        await handlers.handle_web_fetch(WebFetchParams(url="https://example.com"), ctx)
    ).ok is True
    assert (
        await handlers.handle_realitycheck_search(RealityCheckSearchParams(query="rc"), ctx)
    ).ok is True
    assert (
        await handlers.handle_realitycheck_read(RealityCheckReadParams(path="x"), ctx)
    ).ok is True
    assert (await handlers.handle_fs_list(FsListParams(path="."), ctx)).ok is True
    assert (await handlers.handle_fs_read(FsReadParams(path="README.md"), ctx)).ok is True
    assert (
        await handlers.handle_fs_write(FsWriteParams(path="x", content="y", confirm=True), ctx)
    ).ok is True
    assert (await handlers.handle_git_status(GitStatusParams(repo_path="."), ctx)).ok is True
    assert (
        await handlers.handle_git_diff(GitDiffParams(repo_path=".", ref="HEAD"), ctx)
    ).ok is True
    assert (await handlers.handle_git_log(GitLogParams(repo_path=".", limit=1), ctx)).ok is True


@pytest.mark.asyncio
async def test_dashboard_impl_mixin_smoke() -> None:
    class DummyAuditLog:
        def query(self, **_: Any) -> list[dict[str, Any]]:
            return [{"event_type": "x"}]

        def verify_chain(self) -> tuple[bool, int, str]:
            return True, 1, ""

        @staticmethod
        def parse_since(value: Any) -> Any:
            return value

    class DummyDashboard:
        def audit_explorer(self, query: Any) -> dict[str, Any]:
            _ = query
            return {"events": [], "total": 0}

        def blocked_or_flagged_egress(self, *, limit: int) -> dict[str, Any]:
            return {"limit": limit, "events": []}

        def skill_provenance(self, *, limit: int) -> dict[str, Any]:
            return {
                "limit": limit,
                "events": [
                    {
                        "event_type": "SkillInstalled",
                        "timestamp": "t",
                        "data": {
                            "skill_name": "demo",
                            "version": "1.0.0",
                            "signature_status": "trusted",
                            "capabilities": {"net": ["example.com"]},
                            "status": "ok",
                        },
                    }
                ],
            }

        def alerts(self, *, limit: int) -> dict[str, Any]:
            return {"limit": limit, "alerts": []}

        def mark_false_positive(self, *, event_id: str, reason: str) -> None:
            _ = (event_id, reason)

    class DummyInstalled:
        def model_dump(self, *, mode: str) -> dict[str, Any]:
            _ = mode
            return {"name": "demo", "version": "1.0.0"}

    class DummySkillManager:
        def list_installed(self) -> list[DummyInstalled]:
            return [DummyInstalled()]

    class DummyImpl(DashboardImplMixin):
        def __init__(self) -> None:
            self._audit_log = DummyAuditLog()
            self._dashboard = DummyDashboard()
            self._skill_manager = DummySkillManager()

    impl = DummyImpl()
    assert (await impl.do_audit_query({"since": "1h"}))["total"] == 1
    explorer = await impl.do_dashboard_audit_explorer({"since": "1h", "limit": 1})
    assert explorer["hash_chain"]["valid"] is True
    assert (await impl.do_dashboard_egress_review({"limit": 2}))["limit"] == 2
    skill_prov = await impl.do_dashboard_skill_provenance({"limit": 2})
    assert skill_prov["installed"][0]["name"] == "demo"
    assert skill_prov["timeline"][0]["skill_name"] == "demo"
    assert (await impl.do_dashboard_alerts({"limit": 3}))["limit"] == 3
    with pytest.raises(ValueError):
        await impl.do_dashboard_mark_false_positive({"event_id": ""})
    assert (await impl.do_dashboard_mark_false_positive({"event_id": "e1"}))["marked"] is True


@dataclass(frozen=True)
class _DummyManifest:
    name: str = "demo"
    version: str = "1.0.0"
    source_repo: str = "example/repo"
    author: str = "alice"

    def manifest_hash(self) -> str:
        return "deadbeef"


class _DummyEventBus:
    def __init__(self) -> None:
        self.events: list[Any] = []

    async def publish(self, event: Any) -> None:
        self.events.append(event)


@dataclass
class _DummySkillState:
    value: str


@dataclass
class _DummyInstalledSkill:
    name: str
    state: _DummySkillState

    def model_dump(self, *, mode: str) -> dict[str, Any]:
        _ = mode
        return {"name": self.name, "state": self.state.value}


@dataclass
class _DummyDecision:
    allowed: bool = True

    def model_dump(self, *, mode: str) -> dict[str, Any]:
        _ = mode
        return {
            "allowed": self.allowed,
            "status": "installed" if self.allowed else "review",
            "artifact_state": "installed" if self.allowed else "review",
            "findings": [],
            "manifest": {"name": "demo", "version": "1.0.0", "source_repo": "example/repo"},
        }


class _DummyProfile:
    def to_json(self) -> dict[str, Any]:
        return {
            "network_domains": [{"domain": "example.com"}],
            "filesystem_paths": [{"path": "/tmp"}],
            "shell_commands": [{"command": "echo hi"}],
            "environment_vars": [{"var": "FOO"}],
        }


@dataclass
class _DummyProfileResult:
    profile: _DummyProfile


class _DummyReputationScorer:
    def __init__(self, *, allow: bool) -> None:
        self._allow = allow
        self.submissions: list[str] = []

    def can_submit(self, *, author_id: str) -> bool:
        _ = author_id
        return self._allow

    def record_submission(self, *, author_id: str) -> None:
        self.submissions.append(author_id)


class _DummySkillManager:
    def __init__(self, *, installed: list[_DummyInstalledSkill], decision: _DummyDecision) -> None:
        self._installed = installed
        self._decision = decision

    def list_installed(self) -> list[_DummyInstalledSkill]:
        return list(self._installed)

    def review(self, _path: Path) -> dict[str, Any]:
        return {
            "signature": "trusted",
            "findings": [{"id": "f1"}, "ignore"],
            "manifest": {"name": "demo", "version": "1.0.0", "source_repo": "example/repo"},
        }

    async def install(self, _path: Path, *, approve_untrusted: bool) -> _DummyDecision:
        _ = approve_untrusted
        return self._decision

    def profile(self, _path: Path) -> _DummyProfileResult:
        return _DummyProfileResult(profile=_DummyProfile())

    def revoke(self, *, skill_name: str, reason: str) -> _DummyInstalledSkill | None:
        _ = reason
        for item in self._installed:
            if item.name == skill_name:
                item.state = _DummySkillState("revoked")  # type: ignore[misc]
                return item
        return None


@pytest.mark.asyncio
async def test_skills_impl_mixin_smoke(tmp_path: Path) -> None:
    skill_dir = tmp_path / "skill"
    skill_dir.mkdir()

    event_bus = _DummyEventBus()
    installed = [_DummyInstalledSkill(name="demo", state=_DummySkillState("installed"))]
    manager = _DummySkillManager(installed=installed, decision=_DummyDecision(allowed=True))

    class DummySkills(SkillsImplMixin):
        def __init__(self, *, allow_submit: bool) -> None:
            self._event_bus = event_bus
            self._skill_manager = manager
            self._reputation_scorer = _DummyReputationScorer(allow=allow_submit)

        def _load_skill_manifest(self, _path: Path) -> _DummyManifest:
            return _DummyManifest()

        def _skill_reputation(
            self,
            *,
            manifest: _DummyManifest,
            signature_status: str,
            findings: list[dict[str, Any]],
        ) -> str:
            _ = (manifest, signature_status, findings)
            return "ok"

    limited = DummySkills(allow_submit=False)
    assert (await limited.do_skill_list({}))["count"] == 1
    reviewed = await limited.do_skill_review({"skill_path": str(skill_dir)})
    assert reviewed["reputation"] == "ok"
    assert any(isinstance(event, SkillReviewRequested) for event in event_bus.events)

    payload = await limited.do_skill_install({"skill_path": str(skill_dir)})
    assert payload["allowed"] is False
    assert any(isinstance(event, SkillInstalled) for event in event_bus.events)

    allowed = DummySkills(allow_submit=True)
    payload2 = await allowed.do_skill_install(
        {
            "skill_path": str(skill_dir),
            "approve_untrusted": True,
        }
    )
    assert payload2["allowed"] is True

    profiled = await allowed.do_skill_profile({"skill_path": str(skill_dir)})
    assert "network_domains" in profiled
    assert any(isinstance(event, SkillProfiled) for event in event_bus.events)

    revoked = await allowed.do_skill_revoke({"skill_name": "demo"})
    assert revoked["revoked"] is True
    assert any(isinstance(event, SkillRevoked) for event in event_bus.events)
