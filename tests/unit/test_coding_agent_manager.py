from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from shisad.coding.adapter import CodingAgentAdapter
from shisad.coding.manager import CodingAgentManager
from shisad.coding.models import CodingAgentConfig, CodingAgentResult, CodingAgentRunOutput


class _TransportErrorAdapter(CodingAgentAdapter):
    async def run(
        self,
        *,
        prompt_text: str,
        workdir: Path,
        config: CodingAgentConfig,
    ) -> CodingAgentRunOutput:
        _ = (workdir, config)
        return CodingAgentRunOutput(
            result=CodingAgentResult(
                agent="codex",
                task=prompt_text,
                success=False,
                summary="Coding agent failed during ACP negotiation.",
            ),
            error_code="protocol_error",
            transport_error={
                "kind": "request_error",
                "code": -32000,
                "message": "Authentication required",
                "data": {"missing_env": ["OPENAI_API_KEY"]},
            },
        )


class _WriteActivityNoWorktreeDiffAdapter(CodingAgentAdapter):
    async def run(
        self,
        *,
        prompt_text: str,
        workdir: Path,
        config: CodingAgentConfig,
    ) -> CodingAgentRunOutput:
        _ = (workdir, config)
        return CodingAgentRunOutput(
            result=CodingAgentResult(
                agent="codex",
                task=prompt_text,
                success=True,
                summary="Coding agent wrote files in the requested external directory.",
            ),
            raw_updates=(
                {
                    "session_id": "agent-session",
                    "update": {
                        "session_update": "tool_call_update",
                        "kind": "edit",
                        "status": "completed",
                        "content": [
                            {
                                "type": "diff",
                                "path": "/tmp/external-project/pyproject.toml",
                            }
                        ],
                    },
                },
            ),
        )


def _init_hostile_filter_repo(
    tmp_path: Path,
    *,
    required: bool,
) -> tuple[Path, dict[str, Path]]:
    repo = tmp_path / ("required-repo" if required else "optional-repo")
    repo.mkdir()
    subprocess.run(["git", "-C", str(repo), "init"], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(repo), "config", "user.email", "test@example.com"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(repo), "config", "user.name", "Test User"],
        check=True,
    )
    (repo / ".gitattributes").write_text("payload.txt filter=poison\n", encoding="utf-8")
    (repo / "payload.txt").write_text("payload\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    subprocess.run(
        ["git", "-C", str(repo), "commit", "-m", "init"],
        check=True,
        capture_output=True,
    )

    markers = {
        "filter": tmp_path / f"{'required' if required else 'optional'}-filter.marker",
        "hook": tmp_path / f"{'required' if required else 'optional'}-hook.marker",
        "fsmonitor": tmp_path / f"{'required' if required else 'optional'}-fsmonitor.marker",
    }
    helpers: dict[str, Path] = {}
    for name in ("filter", "fsmonitor"):
        helper = tmp_path / f"{'required' if required else 'optional'}-{name}-helper.py"
        helper.write_text(
            f"#!{sys.executable}\nfrom pathlib import Path\nPath({str(markers[name])!r}).touch()\n",
            encoding="utf-8",
        )
        helper.chmod(0o755)
        helpers[name] = helper
    hooks = tmp_path / f"{'required' if required else 'optional'}-hooks"
    hooks.mkdir()
    post_checkout = hooks / "post-checkout"
    post_checkout.write_text(
        f"#!{sys.executable}\nfrom pathlib import Path\nPath({str(markers['hook'])!r}).touch()\n",
        encoding="utf-8",
    )
    post_checkout.chmod(0o755)

    for key, value in (
        ("filter.poison.clean", helpers["filter"]),
        ("filter.poison.smudge", helpers["filter"]),
        ("filter.poison.process", helpers["filter"]),
        ("filter.poison.required", "true" if required else "false"),
        ("core.hooksPath", hooks),
        ("core.fsmonitor", helpers["fsmonitor"]),
    ):
        subprocess.run(
            ["git", "-C", str(repo), "config", key, str(value)],
            check=True,
        )
    return repo, markers


@pytest.mark.asyncio
async def test_m3_manager_logs_worktree_cleanup_failures(
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    # PLN-L6: this test replaces both `_create_worktree` and
    # `_remove_worktree` so it is asserting the exception-handling
    # contract of `_managed_worktree`, not the worktree mechanics
    # themselves. Pin three things, not just the log text:
    # (1) the yielded path is the expected worktree directory,
    # (2) cleanup failure is NOT re-raised,
    # (3) the log record is at WARNING level.
    manager = CodingAgentManager(repo_root=tmp_path, data_dir=tmp_path / "data")

    create_calls: list[Path] = []

    def _fake_create(path: Path) -> None:
        create_calls.append(path)

    monkeypatch.setattr(manager, "_create_worktree", _fake_create)

    def _remove_worktree(_path: Path) -> None:
        raise RuntimeError("cleanup failed")

    monkeypatch.setattr(manager, "_remove_worktree", _remove_worktree)

    with caplog.at_level("WARNING"):
        async with manager._managed_worktree("task-1") as managed_path:
            assert managed_path == manager.worktree_path_for("task-1")
            assert create_calls == [manager.worktree_path_for("task-1")]

    # (2): control flow returned normally despite the raising cleanup.
    warning_records = [r for r in caplog.records if r.levelname == "WARNING"]
    assert warning_records, "expected a WARNING-level log record"
    assert any(
        "Failed to remove coding-agent worktree" in record.getMessage()
        for record in warning_records
    )


def test_m3_manager_logs_advisory_budget_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    # PLN-L6: test the `_budget_warning` pure function across three
    # behavioral branches, not just one. The prior test only hit the
    # over-budget branch and asserted on the log text.
    with caplog.at_level("WARNING"):
        warning = CodingAgentManager._budget_warning(
            cost_usd=1.25,
            config=CodingAgentConfig(max_budget_usd=0.5),
            agent_name="codex",
        )

    assert warning is not None
    assert "No hard spend stop is enforced by the ACP adapter" in warning
    assert "reported $1.25 cost" in caplog.text
    assert any(record.levelname == "WARNING" for record in caplog.records)


def test_m3_manager_budget_warning_is_none_when_under_budget() -> None:
    # PLN-L6 companion branch: at/under budget → no warning returned and
    # no log emitted. Previously uncovered.
    warning = CodingAgentManager._budget_warning(
        cost_usd=0.4,
        config=CodingAgentConfig(max_budget_usd=0.5),
        agent_name="codex",
    )
    assert warning is None


def test_m3_manager_budget_warning_is_none_when_cost_or_budget_missing() -> None:
    # PLN-L6 companion branch: either side missing → no warning. Pins the
    # short-circuit so a regression that crashed on `None` (or emitted a
    # spurious warning) would surface.
    assert (
        CodingAgentManager._budget_warning(
            cost_usd=None,
            config=CodingAgentConfig(max_budget_usd=0.5),
            agent_name="codex",
        )
        is None
    )
    assert (
        CodingAgentManager._budget_warning(
            cost_usd=5.0,
            config=CodingAgentConfig(max_budget_usd=None),
            agent_name="codex",
        )
        is None
    )


@pytest.mark.asyncio
async def test_m9_manager_persists_adapter_transport_error(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    manager = CodingAgentManager(
        repo_root=tmp_path,
        data_dir=tmp_path / "data",
        registry_overrides={"codex": sys.executable},
        adapter_factory=lambda _spec: _TransportErrorAdapter(),
    )
    monkeypatch.setattr(
        manager,
        "_create_worktree",
        lambda path: path.mkdir(parents=True, exist_ok=True),
    )
    monkeypatch.setattr(manager, "_remove_worktree", lambda _path: None)
    monkeypatch.setattr(
        manager,
        "_collect_worktree_changes",
        lambda _path: ([], ""),
    )

    record = await manager.execute(
        task_session_id="task-transport-error",
        task_description="Review the transport failure.",
        file_refs=("README.md",),
        config=CodingAgentConfig(preferred_agent="codex", read_only=True),
    )

    assert record.error_code == "protocol_error"
    assert isinstance(record.raw_log_payload, dict)
    assert record.raw_log_payload["transport_error"] == {
        "kind": "request_error",
        "code": -32000,
        "message": "Authentication required",
        "data": {"missing_env": ["OPENAI_API_KEY"]},
    }


@pytest.mark.asyncio
async def test_gh80_manager_records_write_activity_without_worktree_diff(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    manager = CodingAgentManager(
        repo_root=tmp_path,
        data_dir=tmp_path / "data",
        registry_overrides={"codex": sys.executable},
        adapter_factory=lambda _spec: _WriteActivityNoWorktreeDiffAdapter(),
    )
    monkeypatch.setattr(
        manager,
        "_create_worktree",
        lambda path: path.mkdir(parents=True, exist_ok=True),
    )
    monkeypatch.setattr(manager, "_remove_worktree", lambda _path: None)
    monkeypatch.setattr(manager, "_collect_worktree_changes", lambda _path: ([], ""))

    record = await manager.execute(
        task_session_id="task-external-write",
        task_description="Build the project at /tmp/external-project.",
        file_refs=(),
        config=CodingAgentConfig(preferred_agent="codex", read_only=False),
    )

    assert record.result.success is True
    assert record.result.files_changed == ()
    assert record.proposal_payload is None
    assert isinstance(record.raw_log_payload, dict)
    assert record.raw_log_payload["write_activity_count"] == 1


@pytest.mark.skipif(os.name != "posix", reason="hostile executable helper fixture is POSIX")
def test_f4c_manager_worktree_disables_optional_filters_hooks_and_fsmonitor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo, markers = _init_hostile_filter_repo(tmp_path, required=False)
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "core.hooksPath")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", str(tmp_path / "ambient-hooks"))
    manager = CodingAgentManager(repo_root=repo, data_dir=tmp_path / "data")
    worktree = manager.worktree_path_for("optional-filter")

    try:
        manager._create_worktree(worktree)
        assert (worktree / "payload.txt").read_text(encoding="utf-8") == "payload\n"
        (worktree / "payload.txt").write_text("changed\n", encoding="utf-8")
        files, diff = manager._collect_worktree_changes(worktree)
        assert files == ["payload.txt"]
        assert "changed" in diff
        assert all(not marker.exists() for marker in markers.values())
    finally:
        manager._remove_worktree(worktree)


@pytest.mark.asyncio
@pytest.mark.skipif(os.name != "posix", reason="hostile executable filter fixture is POSIX")
async def test_f4c_manager_blocks_required_executable_filter_actionably(
    tmp_path: Path,
) -> None:
    repo, markers = _init_hostile_filter_repo(tmp_path, required=True)
    manager = CodingAgentManager(
        repo_root=repo,
        data_dir=tmp_path / "data",
        registry_overrides={"codex": sys.executable},
        adapter_factory=lambda _spec: _TransportErrorAdapter(),
    )

    record = await manager.execute(
        task_session_id="required-filter",
        task_description="Inspect the repository.",
        file_refs=("payload.txt",),
        config=CodingAgentConfig(preferred_agent="codex", read_only=True),
    )

    assert record.result.success is False
    assert record.error_code == "worktree_filter_required"
    assert "required executable Git filter 'poison'" in record.result.summary
    assert "disable the filter or use a separately audited checkout" in record.result.summary
    assert not manager.worktree_path_for("required-filter").exists()
    assert all(not marker.exists() for marker in markers.values())
