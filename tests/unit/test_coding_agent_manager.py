from __future__ import annotations

from pathlib import Path

import pytest

from shisad.coding.manager import CodingAgentManager
from shisad.coding.models import CodingAgentConfig


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
