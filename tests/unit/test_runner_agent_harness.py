"""Repo guardrails for the checked-in agent runner harness.

This harness is part of the M5 operator path: it lets agentic coders start a live
daemon, tail logs/events, and send session messages consistently.
"""

from __future__ import annotations

from pathlib import Path


def test_runner_harness_files_exist_and_are_documented() -> None:
    readme = Path("runner/README.md")
    skill = Path("runner/SKILL.md")
    harness = Path("runner/harness.sh")
    env_example = Path("runner/.env.example")
    runbook = Path("runner/RUNBOOK.md")
    entrypoint = Path("runner/daemon_entrypoint.sh")

    assert readme.exists()
    assert skill.exists()
    assert harness.exists()
    assert env_example.exists()
    assert runbook.exists()
    assert entrypoint.exists()

    readme_text = readme.read_text(encoding="utf-8")
    skill_text = skill.read_text(encoding="utf-8")
    harness_text = harness.read_text(encoding="utf-8")
    runbook_text = runbook.read_text(encoding="utf-8")

    assert "runner/harness.sh" in readme_text
    assert "runner/harness.sh" in skill_text
    assert "uv run shisad" in harness_text
    assert "RUNNER_INHERIT_SHISAD_ENV" in harness_text
    assert "SHISAD_DISCORD_ENABLED" in harness_text
    assert "tmux" in harness_text
    assert "v0.4 M5 Runbook" in runbook_text
