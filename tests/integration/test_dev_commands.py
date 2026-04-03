"""Integration coverage for the v0.4 M4 dev-loop control API surface."""

from __future__ import annotations

import asyncio
import os
import sys
from contextlib import suppress
from pathlib import Path
from typing import Any

import pytest

from shisad.core.api.transport import ControlClient
from shisad.core.config import DaemonConfig
from shisad.daemon.runner import run_daemon


async def _wait_for_socket(path: Path, timeout: float = 2.0) -> None:
    end = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < end:
        if path.exists():
            return
        await asyncio.sleep(0.01)
    raise TimeoutError(f"Timed out waiting for socket {path}")


async def _start_daemon(
    tmp_path: Path,
    *,
    policy_text: str,
    config_overrides: dict[str, Any] | None = None,
) -> tuple[asyncio.Task[None], ControlClient]:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(policy_text, encoding="utf-8")
    config_kwargs: dict[str, Any] = {
        "data_dir": tmp_path / "data",
        "socket_path": tmp_path / "control.sock",
        "policy_path": policy_path,
        "log_level": "INFO",
    }
    if config_overrides:
        config_kwargs.update(config_overrides)
    config = DaemonConfig(**config_kwargs)
    daemon_task = asyncio.create_task(run_daemon(config))
    client = ControlClient(config.socket_path)
    await _wait_for_socket(config.socket_path)
    await client.connect()
    return daemon_task, client


async def _shutdown_daemon(daemon_task: asyncio.Task[None], client: ControlClient) -> None:
    with suppress(Exception):
        await client.call("daemon.shutdown")
    await client.close()
    await asyncio.wait_for(daemon_task, timeout=3)


async def _wait_for_event(
    client: ControlClient,
    *,
    event_type: str,
    predicate: Any,
    timeout: float = 4.0,
) -> dict[str, Any]:
    end = asyncio.get_running_loop().time() + timeout
    latest: list[dict[str, Any]] = []
    while asyncio.get_running_loop().time() < end:
        result = await client.call("audit.query", {"event_type": event_type, "limit": 50})
        latest = [dict(event) for event in result.get("events", [])]
        for event in latest:
            if predicate(event):
                return event
        await asyncio.sleep(0.1)
    raise AssertionError(f"Timed out waiting for {event_type}: {latest}")


def _policy_with_caps(*caps: str) -> str:
    lines = [
        'version: "1"',
        "default_require_confirmation: false",
        "default_capabilities:",
        *[f"  - {cap}" for cap in caps],
    ]
    return "\n".join(lines) + "\n"


def _fake_coding_agent_command(agent_name: str, *extra_args: str) -> str:
    script = Path(__file__).resolve().parents[1] / "fixtures" / "fake_acp_agent.py"
    extra = " ".join(extra_args)
    suffix = f" {extra}" if extra else ""
    return f"{sys.executable} {script} --agent-name {agent_name}{suffix}"


@pytest.fixture(autouse=True)
def _force_local_planner_routes(monkeypatch: pytest.MonkeyPatch) -> None:
    # These dev-loop integration tests cover coding-task orchestration, not live
    # provider behavior. Keep the planner local so ambient API keys do not make
    # the suite depend on remote model availability or output variance.
    for key in (
        "SHISAD_MODEL_REMOTE_ENABLED",
        "SHISAD_MODEL_PLANNER_REMOTE_ENABLED",
        "SHISAD_MODEL_EMBEDDINGS_REMOTE_ENABLED",
        "SHISAD_MODEL_MONITOR_REMOTE_ENABLED",
    ):
        monkeypatch.setenv(key, "false")
    for key in (
        "SHISA_API_KEY",
        "OPENAI_API_KEY",
        "OPENROUTER_API_KEY",
        "GEMINI_API_KEY",
        "SHISAD_MODEL_API_KEY",
        "SHISAD_MODEL_PLANNER_API_KEY",
        "SHISAD_MODEL_EMBEDDINGS_API_KEY",
        "SHISAD_MODEL_MONITOR_API_KEY",
    ):
        if key in os.environ:
            monkeypatch.delenv(key)


@pytest.mark.asyncio
async def test_m4_dev_commands_reuse_live_coding_task_runtime(tmp_path: Path) -> None:
    readme_before = Path("README.md").read_text(encoding="utf-8")
    daemon_task, client = await _start_daemon(
        tmp_path,
        policy_text=_policy_with_caps("file.read", "file.write", "shell.exec", "http.request"),
        config_overrides={
            "coding_repo_root": Path.cwd(),
            "coding_agent_registry_overrides": {
                "codex": _fake_coding_agent_command("codex"),
                "claude": _fake_coding_agent_command("claude"),
            },
        },
    )
    try:
        implement = await client.call(
            "dev.implement",
            {
                "task": "Add a tiny implementation note to README.md.",
                "file_refs": ["README.md"],
                "agent": "codex",
            },
        )
        assert implement["success"] is True
        assert implement["operation"] == "implement"
        assert implement["proposal_ref"]
        assert implement["raw_log_ref"]
        assert implement["task_session_id"]
        assert "mode=build" in implement["summary"]
        assert Path("README.md").read_text(encoding="utf-8") == readme_before

        selected = await _wait_for_event(
            client,
            event_type="CodingAgentSessionCompleted",
            predicate=lambda item: (
                str(item.get("session_id", "")).strip() == str(implement["task_session_id"])
            ),
        )
        assert selected["data"]["agent"] == "codex"
        assert selected["data"]["success"] is True

        review = await client.call(
            "dev.review",
            {
                "scope": "Review README.md for issues. OPPORTUNISTIC_EDIT if needed.",
                "file_refs": ["README.md"],
                "agent": "claude",
            },
        )
        assert review["success"] is True
        assert review["operation"] == "review"
        assert review["proposal_ref"]
        assert review["findings"]
        assert "mode=plan" in review["summary"]

        remediate = await client.call(
            "dev.remediate",
            {
                "findings": "Fix the README.md note and keep the change proposal-first.",
                "file_refs": ["README.md"],
                "agent": "codex",
            },
        )
        assert remediate["success"] is True
        assert remediate["operation"] == "remediate"
        assert remediate["proposal_ref"]
        assert "mode=build" in remediate["summary"]
    finally:
        await _shutdown_daemon(daemon_task, client)


@pytest.mark.asyncio
async def test_m4_dev_close_reports_requested_doc_readiness(tmp_path: Path) -> None:
    daemon_task, client = await _start_daemon(
        tmp_path,
        policy_text=_policy_with_caps("file.read"),
    )
    implementation = tmp_path / "IMPLEMENTATION.md"
    implementation.write_text(
        """
## M4 — Minimal Dev Loop Orchestration

### M4 Punchlist
- [x] dev.implement works

### M4 Acceptance Criteria
- [x] Runtime wiring evidence recorded.
- [x] Validation evidence recorded.
- [x] Docs parity evidence recorded.
- [x] Review loop complete or deferrals explicitly recorded.

### M4 Review Findings Status (Round 1)
- [x] M4.R-open.1: closed.

### M4 Runtime Wiring Evidence
- Wired.

### M4 Validation Evidence
- `uv run pytest tests/behavioral/ -q` -> `ok`

## Worklog

- **2026-03-14**: **M4 implementation**
  - Summary: docs updated.
""".strip(),
        encoding="utf-8",
    )
    try:
        ready = await client.call(
            "dev.close",
            {"milestone": "M4", "implementation_path": str(implementation)},
        )
        assert ready["ready"] is True
        assert ready["open_finding_ids"] == []

        missing = await client.call(
            "dev.close",
            {
                "milestone": "M4",
                "implementation_path": str(tmp_path / "missing.md"),
            },
        )
        assert missing["ready"] is False
        assert missing["missing_evidence"] == ["implementation_doc_missing"]
    finally:
        await _shutdown_daemon(daemon_task, client)


@pytest.mark.asyncio
async def test_m4_dev_review_handles_large_acp_messages(tmp_path: Path) -> None:
    daemon_task, client = await _start_daemon(
        tmp_path,
        policy_text=_policy_with_caps("file.read", "shell.exec"),
        config_overrides={
            "coding_repo_root": Path.cwd(),
            "coding_agent_registry_overrides": {
                "codex": _fake_coding_agent_command(
                    "codex",
                    "--large-single-line-summary-bytes",
                    "70000",
                ),
            },
        },
    )
    try:
        review = await client.call(
            "dev.review",
            {
                "scope": "Review README.md and keep the response short.",
                "file_refs": ["README.md"],
                "agent": "codex",
            },
        )
        assert review["success"] is True
        assert review["operation"] == "review"
        assert review["summary"].startswith("codex large-response mode=plan ")
        assert len(review["summary"]) <= 320
    finally:
        await _shutdown_daemon(daemon_task, client)


@pytest.mark.asyncio
async def test_m4_dev_review_passes_agent_auth_env(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-anthropic-key")
    daemon_task, client = await _start_daemon(
        tmp_path,
        policy_text=_policy_with_caps("file.read", "shell.exec"),
        config_overrides={
            "coding_repo_root": Path.cwd(),
            "coding_agent_registry_overrides": {
                "claude": _fake_coding_agent_command(
                    "claude",
                    "--require-env",
                    "ANTHROPIC_API_KEY",
                ),
            },
        },
    )
    try:
        review = await client.call(
            "dev.review",
            {
                "scope": "Review README.md and keep the response short.",
                "file_refs": ["README.md"],
                "agent": "claude",
            },
        )
        assert review["success"] is True
        assert review["operation"] == "review"
        assert review["agent"] == "claude"
        assert "mode=plan" in review["summary"]
    finally:
        await _shutdown_daemon(daemon_task, client)
