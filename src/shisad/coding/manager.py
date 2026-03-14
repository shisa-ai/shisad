"""High-level coding-agent task execution manager."""

from __future__ import annotations

import asyncio
import subprocess
from collections.abc import Callable, Mapping
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .acp_adapter import AcpAdapter
from .adapter import CodingAgentAdapter
from .models import CodingAgentConfig, CodingAgentResult
from .registry import (
    AgentCommandSpec,
    AgentSelectionAttempt,
    AgentSelectionResult,
    build_default_agent_registry,
    select_coding_agent,
)


@dataclass(frozen=True, slots=True)
class CodingAgentExecutionRecord:
    result: CodingAgentResult
    error_code: str = ""
    stop_reason: str = ""
    selected_agent: str = ""
    attempts: tuple[AgentSelectionAttempt, ...] = ()
    fallback_used: bool = False
    worktree_path: str = ""
    raw_log_payload: dict[str, Any] | None = None
    proposal_payload: dict[str, Any] | None = None


def _run_subprocess(
    command: list[str],
    *,
    cwd: Path | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=str(cwd) if cwd is not None else None,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=check,
    )


def _status_paths(status_output: str) -> list[str]:
    files: list[str] = []
    for line in status_output.splitlines():
        if len(line) < 4:
            continue
        payload = line[3:].strip()
        if not payload:
            continue
        if " -> " in payload:
            payload = payload.rsplit(" -> ", 1)[-1].strip()
        if payload not in files:
            files.append(payload)
    return files


def _diff_untracked_file(worktree_path: Path, relative_path: str) -> str:
    result = _run_subprocess(
        [
            "git",
            "diff",
            "--no-index",
            "--binary",
            "--no-color",
            "--",
            "/dev/null",
            relative_path,
        ],
        cwd=worktree_path,
        check=False,
    )
    if result.returncode not in {0, 1}:
        raise subprocess.CalledProcessError(
            result.returncode,
            result.args,
            output=result.stdout,
            stderr=result.stderr,
        )
    return result.stdout.strip()


class CodingAgentManager:
    """Create isolated worktrees and execute coding tasks through adapters."""

    def __init__(
        self,
        *,
        repo_root: Path,
        data_dir: Path,
        registry_overrides: Mapping[str, str] | None = None,
        adapter_factory: Callable[[AgentCommandSpec], CodingAgentAdapter] | None = None,
    ) -> None:
        self._repo_root = repo_root
        self._worktree_root = data_dir / "coding_worktrees"
        self._worktree_root.mkdir(parents=True, exist_ok=True)
        self._registry = build_default_agent_registry(registry_overrides)
        self._adapter_factory = adapter_factory or (lambda spec: AcpAdapter(spec=spec))

    def select_agent(self, config: CodingAgentConfig) -> AgentSelectionResult:
        return select_coding_agent(registry=self._registry, config=config)

    async def execute(
        self,
        *,
        task_session_id: str,
        task_description: str,
        file_refs: tuple[str, ...],
        config: CodingAgentConfig,
        selection: AgentSelectionResult | None = None,
    ) -> CodingAgentExecutionRecord:
        resolved_selection = selection or self.select_agent(config)
        if resolved_selection.spec is None:
            attempted = ", ".join(
                f"{attempt.agent} ({attempt.reason})" for attempt in resolved_selection.attempts
            )
            summary = "Requested coding agent is not available."
            if attempted:
                summary = f"{summary} Attempted: {attempted}."
            return CodingAgentExecutionRecord(
                result=CodingAgentResult(
                    agent=config.preferred_agent or "",
                    task=task_description,
                    success=False,
                    summary=summary,
                ),
                error_code="agent_unavailable",
                attempts=resolved_selection.attempts,
            )

        prompt_text = self._build_prompt(
            task_description=task_description,
            file_refs=file_refs,
            config=config,
        )
        async with self._managed_worktree(task_session_id) as worktree_path:
            adapter = self._adapter_factory(resolved_selection.spec)
            adapter_output = await adapter.run(
                prompt_text=prompt_text,
                workdir=worktree_path,
                config=config,
            )
            files_changed = await asyncio.to_thread(self._files_changed, worktree_path)
            diff_text = await asyncio.to_thread(self._proposal_diff, worktree_path)
            proposal_payload: dict[str, Any] | None = None
            if diff_text:
                proposal_payload = {
                    "agent": resolved_selection.spec.name,
                    "task": task_description,
                    "files_changed": files_changed,
                    "diff": diff_text,
                    "read_only": config.read_only,
                    "task_kind": config.task_kind,
                }
            raw_log_payload = {
                "agent": resolved_selection.spec.name,
                "task": task_description,
                "file_refs": list(file_refs),
                "selected_mode": adapter_output.selected_mode,
                "applied_config": dict(adapter_output.applied_config),
                "stop_reason": adapter_output.stop_reason,
                "error_code": adapter_output.error_code,
                "updates": list(adapter_output.raw_updates),
                "attempts": [
                    {
                        "agent": attempt.agent,
                        "available": attempt.available,
                        "reason": attempt.reason,
                    }
                    for attempt in resolved_selection.attempts
                ],
            }
            result = CodingAgentResult(
                agent=resolved_selection.spec.name,
                task=adapter_output.result.task,
                success=adapter_output.result.success,
                summary=adapter_output.result.summary,
                files_changed=tuple(files_changed),
                cost=adapter_output.result.cost,
                duration_ms=adapter_output.result.duration_ms,
            )
            return CodingAgentExecutionRecord(
                result=result,
                error_code=adapter_output.error_code,
                stop_reason=adapter_output.stop_reason,
                selected_agent=resolved_selection.spec.name,
                attempts=resolved_selection.attempts,
                fallback_used=resolved_selection.fallback_used,
                worktree_path=str(worktree_path),
                raw_log_payload=raw_log_payload,
                proposal_payload=proposal_payload,
            )

    @asynccontextmanager
    async def _managed_worktree(self, task_session_id: str) -> Any:
        worktree_path = self._worktree_root / task_session_id
        await asyncio.to_thread(self._create_worktree, worktree_path)
        try:
            yield worktree_path
        finally:
            with suppress(Exception):
                await asyncio.to_thread(self._remove_worktree, worktree_path)

    def _create_worktree(self, worktree_path: Path) -> None:
        if worktree_path.exists():
            self._remove_worktree(worktree_path)
        worktree_path.parent.mkdir(parents=True, exist_ok=True)
        _run_subprocess(
            [
                "git",
                "-C",
                str(self._repo_root),
                "worktree",
                "add",
                "--detach",
                str(worktree_path),
                "HEAD",
            ]
        )

    def _remove_worktree(self, worktree_path: Path) -> None:
        _run_subprocess(
            [
                "git",
                "-C",
                str(self._repo_root),
                "worktree",
                "remove",
                "--force",
                str(worktree_path),
            ],
            check=False,
        )

    @staticmethod
    def _build_prompt(
        *,
        task_description: str,
        file_refs: tuple[str, ...],
        config: CodingAgentConfig,
    ) -> str:
        lines = [
            f"TASK KIND: {config.task_kind}",
            f"READ ONLY INTENT: {'yes' if config.read_only else 'no'}",
            "FILES:",
        ]
        lines.extend(f"- {file_ref}" for file_ref in file_refs)
        lines.extend(
            [
                "INSTRUCTIONS:",
                task_description.strip() or "Complete the coding task.",
            ]
        )
        return "\n".join(lines).strip()

    @staticmethod
    def _files_changed(worktree_path: Path) -> list[str]:
        result = _run_subprocess(
            [
                "git",
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
            ],
            cwd=worktree_path,
        )
        return _status_paths(result.stdout)

    @staticmethod
    def _proposal_diff(worktree_path: Path) -> str:
        status_output = _run_subprocess(
            [
                "git",
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
            ],
            cwd=worktree_path,
        ).stdout
        changed_files = _status_paths(status_output)
        tracked_diff = _run_subprocess(
            [
                "git",
                "diff",
                "--binary",
                "--no-color",
                "HEAD",
                "--",
            ],
            cwd=worktree_path,
        ).stdout.strip()
        untracked_files = [
            path
            for line, path in zip(status_output.splitlines(), changed_files, strict=False)
            if line.startswith("??")
        ]
        diff_parts = [tracked_diff] if tracked_diff else []
        for path in untracked_files:
            diff = _diff_untracked_file(worktree_path, path)
            if diff:
                diff_parts.append(diff)
        return "\n".join(part for part in diff_parts if part).strip()
