#!/usr/bin/env python3
"""Generate release stats rollup JSON for a git ref range."""

from __future__ import annotations

import argparse
import ast
import json
import subprocess
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def _run_git(repo_root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=repo_root,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout


def _parse_numstat(output: str) -> tuple[int, int]:
    insertions = 0
    deletions = 0
    for line in output.splitlines():
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        added, removed = parts[0], parts[1]
        if not added.isdigit() or not removed.isdigit():
            continue
        insertions += int(added)
        deletions += int(removed)
    return insertions, deletions


def _git_stats(repo_root: Path, from_ref: str, to_ref: str) -> dict[str, Any]:
    range_spec = f"{from_ref}..{to_ref}"
    commits_in_range = int(_run_git(repo_root, "rev-list", "--count", range_spec).strip())
    commits_to_ref = int(_run_git(repo_root, "rev-list", "--count", to_ref).strip())
    files_output = _run_git(repo_root, "log", "--name-only", "--pretty=format:", range_spec)
    unique_files = {line.strip() for line in files_output.splitlines() if line.strip()}
    numstat_output = _run_git(repo_root, "log", "--pretty=tformat:", "--numstat", range_spec)
    insertions, deletions = _parse_numstat(numstat_output)
    tag_commit = _run_git(repo_root, "rev-parse", "--short", to_ref).strip()
    return {
        "from_ref": from_ref,
        "to_ref": to_ref,
        "range": range_spec,
        "to_commit": tag_commit,
        "commits_in_range": commits_in_range,
        "commits_to_ref": commits_to_ref,
        "unique_files_touched": len(unique_files),
        "insertions": insertions,
        "deletions": deletions,
        "net_lines": insertions - deletions,
    }


def _count_codebase(repo_root: Path) -> dict[str, Any]:
    scopes = ("src", "tests", "scripts")
    by_scope: dict[str, dict[str, int]] = {}
    total_files = 0
    total_lines = 0
    for scope in scopes:
        root = repo_root / scope
        files = list(root.rglob("*.py")) if root.exists() else []
        line_count = 0
        for file in files:
            try:
                line_count += len(file.read_text(encoding="utf-8").splitlines())
            except OSError:
                continue
        by_scope[scope] = {"python_files": len(files), "python_lines": line_count}
        total_files += len(files)
        total_lines += line_count
    return {
        "python_files": total_files,
        "python_lines": total_lines,
        "by_scope": by_scope,
    }


def _count_tests_in_file(path: Path) -> int:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, SyntaxError):
        return 0
    count = 0
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith(
            "test_"
        ):
            count += 1
            continue
        if isinstance(node, ast.ClassDef) and node.name.startswith("Test"):
            for child in node.body:
                is_collectable = isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) and (
                    child.name.startswith("test_")
                )
                if is_collectable:
                    count += 1
    return count


def _test_stats(repo_root: Path, tests_root: Path) -> dict[str, Any]:
    categories = ("unit", "integration", "adversarial")
    by_category: dict[str, dict[str, int]] = {}
    total_files = 0
    total_functions = 0
    for category in categories:
        category_root = tests_root / category
        files = sorted(
            {
                path
                for pattern in ("test_*.py", "*_test.py")
                for path in category_root.rglob(pattern)
                if path.is_file()
            }
        )
        functions = sum(_count_tests_in_file(path) for path in files)
        by_category[category] = {"test_files": len(files), "test_functions": functions}
        total_files += len(files)
        total_functions += functions
    normalized_root = tests_root.relative_to(repo_root) if tests_root.is_absolute() else tests_root
    return {
        "tests_root": str(normalized_root),
        "test_files": total_files,
        "test_functions": total_functions,
        "by_category": by_category,
    }


def _except_exception_count(src_root: Path) -> int:
    count = 0
    for path in src_root.rglob("*.py"):
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        count += text.count("except Exception")
    return count


@dataclass
class SessionSummary:
    session_file: str
    first_timestamp_utc: str
    last_timestamp_utc: str
    duration_minutes: float
    event_types: dict[str, int]
    response_item_types: dict[str, int]
    tool_call_counts: dict[str, int]
    tool_calls: int
    tool_outputs: int
    assistant_messages: int
    user_messages: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "session_file": self.session_file,
            "first_timestamp_utc": self.first_timestamp_utc,
            "last_timestamp_utc": self.last_timestamp_utc,
            "duration_minutes": self.duration_minutes,
            "event_types": self.event_types,
            "response_item_types": self.response_item_types,
            "tool_call_counts": self.tool_call_counts,
            "tool_calls": self.tool_calls,
            "tool_outputs": self.tool_outputs,
            "assistant_messages": self.assistant_messages,
            "user_messages": self.user_messages,
        }


def _find_session_file(codex_root: Path, session_id: str) -> Path | None:
    matches = sorted(codex_root.rglob(f"*{session_id}*.jsonl"))
    return matches[0] if matches else None


def _parse_timestamp(raw: str) -> datetime:
    return datetime.fromisoformat(raw.replace("Z", "+00:00")).astimezone(UTC)


def _session_stats(
    session_path: Path,
    *,
    start_utc: datetime | None = None,
    end_utc: datetime | None = None,
) -> SessionSummary:
    first_ts: datetime | None = None
    last_ts: datetime | None = None
    event_types: Counter[str] = Counter()
    response_item_types: Counter[str] = Counter()
    tool_call_counts: Counter[str] = Counter()
    tool_calls = 0
    tool_outputs = 0
    assistant_messages = 0
    user_messages = 0

    for line in session_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        obj = json.loads(line)
        timestamp_raw = obj.get("timestamp")
        ts: datetime | None = None
        if isinstance(timestamp_raw, str):
            ts = _parse_timestamp(timestamp_raw)
            if start_utc is not None and ts < start_utc:
                continue
            if end_utc is not None and ts > end_utc:
                continue
            first_ts = ts if first_ts is None else min(first_ts, ts)
            last_ts = ts if last_ts is None else max(last_ts, ts)

        event_type = obj.get("type")
        if isinstance(event_type, str):
            event_types[event_type] += 1

        payload = obj.get("payload")
        if not isinstance(payload, dict):
            continue

        if event_type == "response_item":
            response_type = payload.get("type")
            if isinstance(response_type, str):
                response_item_types[response_type] += 1
            if response_type == "function_call":
                tool_calls += 1
                tool_name = payload.get("name")
                if isinstance(tool_name, str):
                    tool_call_counts[tool_name] += 1
            elif response_type == "function_call_output":
                tool_outputs += 1
            elif response_type == "message":
                role = payload.get("role")
                if role == "assistant":
                    assistant_messages += 1
                elif role == "user":
                    user_messages += 1
        elif event_type == "event_msg" and payload.get("type") == "user_message":
            user_messages += 1

    if first_ts is None or last_ts is None:
        raise ValueError(f"session file has no timestamps: {session_path}")

    duration_minutes = round((last_ts - first_ts).total_seconds() / 60.0, 2)
    return SessionSummary(
        session_file=str(session_path),
        first_timestamp_utc=first_ts.isoformat(),
        last_timestamp_utc=last_ts.isoformat(),
        duration_minutes=duration_minutes,
        event_types=dict(event_types),
        response_item_types=dict(response_item_types),
        tool_call_counts=dict(tool_call_counts),
        tool_calls=tool_calls,
        tool_outputs=tool_outputs,
        assistant_messages=assistant_messages,
        user_messages=user_messages,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", default=".", help="Repository root")
    parser.add_argument("--from-ref", default="v0.1.0", help="Git start ref")
    parser.add_argument("--to-ref", default="HEAD", help="Git end ref")
    parser.add_argument("--tests-root", default="tests", help="Tests root path")
    parser.add_argument("--session-id", help="Optional Codex session UUID suffix")
    parser.add_argument("--session-file", help="Optional explicit session JSONL path")
    parser.add_argument(
        "--codex-root",
        default="~/.codex/sessions",
        help="Codex session root (used with --session-id)",
    )
    parser.add_argument("--session-start-utc", help="Optional ISO timestamp filter start")
    parser.add_argument("--session-end-utc", help="Optional ISO timestamp filter end")
    parser.add_argument("--output", help="Optional output JSON path")
    args = parser.parse_args()

    repo_root = Path(args.repo_root).resolve()
    tests_root = (repo_root / args.tests_root).resolve()
    src_root = repo_root / "src"

    payload: dict[str, Any] = {
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "git": _git_stats(repo_root, args.from_ref, args.to_ref),
        "codebase": _count_codebase(repo_root),
        "tests": _test_stats(repo_root, tests_root),
        "exceptions": {
            "except_exception_sites": _except_exception_count(src_root),
        },
    }

    session_file: Path | None = None
    if args.session_file:
        session_file = Path(args.session_file).expanduser().resolve()
    elif args.session_id:
        codex_root = Path(args.codex_root).expanduser().resolve()
        session_file = _find_session_file(codex_root, args.session_id)
        if session_file is None:
            raise SystemExit(f"session id not found under {codex_root}: {args.session_id}")

    if session_file is not None:
        if not session_file.exists():
            raise SystemExit(f"session file missing: {session_file}")
        start_utc = _parse_timestamp(args.session_start_utc) if args.session_start_utc else None
        end_utc = _parse_timestamp(args.session_end_utc) if args.session_end_utc else None
        payload["session"] = _session_stats(
            session_file,
            start_utc=start_utc,
            end_utc=end_utc,
        ).as_dict()
        payload["session_filters"] = {
            "start_utc": start_utc.isoformat() if start_utc is not None else None,
            "end_utc": end_utc.isoformat() if end_utc is not None else None,
        }

    text = json.dumps(payload, indent=2, sort_keys=True)
    if args.output:
        output = Path(args.output).expanduser().resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
