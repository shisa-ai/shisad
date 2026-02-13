"""M2 runner structure guardrails."""

from __future__ import annotations

import ast
from pathlib import Path


def test_run_daemon_is_orchestration_only() -> None:
    tree = ast.parse(Path("src/shisad/daemon/runner.py").read_text(encoding="utf-8"))
    run = next(
        node
        for node in tree.body
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "run_daemon"
    )
    length = (run.end_lineno or run.lineno) - run.lineno + 1
    assert length <= 200

    nested = [
        node
        for node in ast.walk(run)
        if node is not run
        and isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
    ]
    assert nested == []


def test_runner_has_no_private_provider_classes() -> None:
    tree = ast.parse(Path("src/shisad/daemon/runner.py").read_text(encoding="utf-8"))
    private_classes = [
        node.name
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name.startswith("_")
    ]
    assert private_classes == []
