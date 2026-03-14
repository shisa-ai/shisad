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
    manager = CodingAgentManager(repo_root=tmp_path, data_dir=tmp_path / "data")

    monkeypatch.setattr(manager, "_create_worktree", lambda path: None)

    def _remove_worktree(_path: Path) -> None:
        raise RuntimeError("cleanup failed")

    monkeypatch.setattr(manager, "_remove_worktree", _remove_worktree)

    with caplog.at_level("WARNING"):
        async with manager._managed_worktree("task-1"):
            pass

    assert "Failed to remove coding-agent worktree" in caplog.text


def test_m3_manager_logs_advisory_budget_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level("WARNING"):
        warning = CodingAgentManager._budget_warning(
            cost_usd=1.25,
            config=CodingAgentConfig(max_budget_usd=0.5),
            agent_name="codex",
        )

    assert warning is not None
    assert "No hard spend stop is enforced by the ACP adapter" in warning
    assert "reported $1.25 cost" in caplog.text
