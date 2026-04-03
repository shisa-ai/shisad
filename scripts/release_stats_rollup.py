#!/usr/bin/env python3
"""Generate release stats rollup JSON for a git ref range."""

from __future__ import annotations

import argparse
import ast
import json
import re
import subprocess
from bisect import bisect_left, bisect_right
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from itertools import pairwise
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
    tag_commit = _run_git(repo_root, "rev-parse", "--short", f"{to_ref}^{{}}").strip()
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


@dataclass(frozen=True)
class CommitEvent:
    timestamp_utc: datetime
    subject: str | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "timestamp_utc": self.timestamp_utc.isoformat(),
            "subject": self.subject,
        }


def _parse_tool_arguments(raw: Any) -> dict[str, Any] | None:
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return None
        return parsed if isinstance(parsed, dict) else None
    return None


@dataclass(frozen=True)
class GitCommit:
    sha: str
    timestamp_utc: datetime
    subject: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "sha": self.sha,
            "sha_short": self.sha[:7],
            "timestamp_utc": self.timestamp_utc.isoformat(),
            "subject": self.subject,
        }


def _git_commit_timeline(repo_root: Path, from_ref: str, to_ref: str) -> list[GitCommit]:
    range_spec = f"{from_ref}..{to_ref}"
    output = _run_git(repo_root, "log", "--reverse", "--format=%H|%cI|%s", range_spec)
    commits: list[GitCommit] = []
    for line in output.splitlines():
        if not line.strip():
            continue
        sha, ts_raw, subject = line.split("|", 2)
        ts = datetime.fromisoformat(ts_raw).astimezone(UTC)
        commits.append(GitCommit(sha=sha, timestamp_utc=ts, subject=subject))
    return commits


_COMMIT_SUBJECT_RE = re.compile(r"(?:^|\s)-m\s+(?:\"([^\"]*)\"|'([^']*)')")
_MILESTONE_RE = re.compile(r"\bM(\d+)\b")
_REMEDIATION_PASS_RE = re.compile(r"\bM(\d+)\.(RR\d+|R-open)\b")
_REMEDIATION_PASS_SPACED_RE = re.compile(r"\bM(\d+)\s+(RR\d+|R-open)\b")


def _extract_git_commit_subjects(cmd: str) -> list[str]:
    subjects: list[str] = []
    for match in re.finditer(r"\bgit\s+commit\b", cmd):
        tail = cmd[match.start() :]
        subject_match = _COMMIT_SUBJECT_RE.search(tail)
        if subject_match is None:
            continue
        subject = subject_match.group(1) or subject_match.group(2)
        if subject is not None:
            subjects.append(subject)
    return subjects


def _milestone_mentions(subject: str) -> set[str]:
    return {f"M{num}" for num in _MILESTONE_RE.findall(subject)}


def _single_milestone(subject: str | None) -> str | None:
    if not subject:
        return None
    mentions = _milestone_mentions(subject)
    return next(iter(mentions)) if len(mentions) == 1 else None


def _is_remediation_related_subject(subject: str | None) -> bool:
    if not subject:
        return False
    lowered = subject.lower()
    if "(remediation)" in lowered:
        return True
    if "re-review closure" in lowered:
        return True
    if _REMEDIATION_PASS_RE.search(subject) is not None:
        return True
    return _REMEDIATION_PASS_SPACED_RE.search(subject) is not None


def _remediation_passes_for_milestone(subject: str, milestone: str) -> set[str]:
    milestone_num = milestone[1:]
    passes: set[str] = set()
    for match_num, match_pass in _REMEDIATION_PASS_RE.findall(subject):
        if match_num == milestone_num:
            passes.add(match_pass)
    for match_num, match_pass in _REMEDIATION_PASS_SPACED_RE.findall(subject):
        if match_num == milestone_num:
            passes.add(match_pass)
    return passes


def _window_activity_breakdown(
    timestamps_sorted: list[datetime],
    *,
    start_utc: datetime,
    end_utc: datetime,
    idle_threshold: timedelta,
) -> tuple[float, float, float]:
    if end_utc <= start_utc:
        return 0.0, 0.0, 0.0

    start_idx = bisect_left(timestamps_sorted, start_utc)
    end_idx = bisect_right(timestamps_sorted, end_utc)
    window = [start_utc, *timestamps_sorted[start_idx:end_idx], end_utc]
    window.sort()

    wall_seconds = (end_utc - start_utc).total_seconds()
    active_seconds = 0.0
    idle_seconds = 0.0
    prev = window[0]
    for current in window[1:]:
        if current <= prev:
            prev = current
            continue
        gap = (current - prev).total_seconds()
        if current - prev > idle_threshold:
            idle_seconds += gap
        else:
            active_seconds += gap
        prev = current

    return wall_seconds, active_seconds, idle_seconds


def _session_timing(
    session_path: Path,
    *,
    repo_root: Path | None = None,
    from_ref: str | None = None,
    to_ref: str | None = None,
    start_utc: datetime | None = None,
    end_utc: datetime | None = None,
    idle_threshold: timedelta = timedelta(minutes=5),
    max_idle_gaps: int = 10,
) -> dict[str, Any]:
    timestamps: list[datetime] = []
    commit_events: list[CommitEvent] = []

    for line in session_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        obj = json.loads(line)
        timestamp_raw = obj.get("timestamp")
        if not isinstance(timestamp_raw, str):
            continue
        ts = _parse_timestamp(timestamp_raw)
        if start_utc is not None and ts < start_utc:
            continue
        if end_utc is not None and ts > end_utc:
            continue
        timestamps.append(ts)

        if obj.get("type") != "response_item":
            continue
        payload = obj.get("payload")
        if not isinstance(payload, dict):
            continue
        if payload.get("type") != "function_call":
            continue
        if payload.get("name") != "exec_command":
            continue

        args = _parse_tool_arguments(payload.get("arguments"))
        if not args:
            continue
        cmd = args.get("cmd")
        if not isinstance(cmd, str) or "git commit" not in cmd:
            continue

        for subject in _extract_git_commit_subjects(cmd):
            commit_events.append(CommitEvent(timestamp_utc=ts, subject=subject))

    if not timestamps:
        raise ValueError(f"session file has no timestamps: {session_path}")

    timestamps.sort()
    commit_events.sort(key=lambda ev: ev.timestamp_utc)

    analysis_start = start_utc if start_utc is not None else timestamps[0]
    analysis_end = end_utc if end_utc is not None else timestamps[-1]

    first_ts = timestamps[0]
    last_ts = timestamps[-1]
    wall_seconds, active_seconds, idle_seconds = _window_activity_breakdown(
        timestamps_sorted=timestamps,
        start_utc=analysis_start,
        end_utc=analysis_end,
        idle_threshold=idle_threshold,
    )

    idle_gaps: list[tuple[datetime, datetime, float]] = []
    window = [analysis_start, *timestamps, analysis_end]
    window.sort()
    prev = window[0]
    for current in window[1:]:
        if current <= prev:
            prev = current
            continue
        if current - prev > idle_threshold:
            idle_gaps.append((prev, current, (current - prev).total_seconds()))
        prev = current

    idle_gaps.sort(key=lambda row: row[2], reverse=True)
    idle_gaps = idle_gaps[: max(0, max_idle_gaps)]

    git_commits_in_window: list[GitCommit] = []
    if repo_root is not None and from_ref is not None and to_ref is not None:
        git_commits = _git_commit_timeline(repo_root, from_ref, to_ref)
        git_commits_in_window = [
            commit
            for commit in git_commits
            if analysis_start <= commit.timestamp_utc <= analysis_end
        ]

    commit_markers: list[tuple[datetime, str | None, str | None]] = [
        (commit.timestamp_utc, commit.subject, commit.sha[:7]) for commit in git_commits_in_window
    ]
    if not commit_markers:
        commit_markers = [(ev.timestamp_utc, ev.subject, None) for ev in commit_events]

    commit_ts = [ts for ts, _, _ in commit_markers]
    idle_gap_rows: list[dict[str, Any]] = []
    for gap_start, gap_end, gap_seconds in idle_gaps:
        prev_commit: tuple[datetime, str | None, str | None] | None = None
        next_commit: tuple[datetime, str | None, str | None] | None = None
        prev_idx = bisect_right(commit_ts, gap_start) - 1
        if prev_idx >= 0:
            prev_commit = commit_markers[prev_idx]
        next_idx = bisect_left(commit_ts, gap_end)
        if 0 <= next_idx < len(commit_markers):
            next_commit = commit_markers[next_idx]
        idle_gap_rows.append(
            {
                "start_utc": gap_start.isoformat(),
                "end_utc": gap_end.isoformat(),
                "duration_minutes": round(gap_seconds / 60.0, 2),
                "prev_commit_sha_short": prev_commit[2] if prev_commit else None,
                "prev_commit_subject": prev_commit[1] if prev_commit else None,
                "next_commit_sha_short": next_commit[2] if next_commit else None,
                "next_commit_subject": next_commit[1] if next_commit else None,
            }
        )

    boundaries: list[tuple[datetime, str]] = [(first_ts, "<session_start>")]
    boundaries.extend((ev.timestamp_utc, ev.subject or "<unknown_commit>") for ev in commit_events)
    boundaries.append((last_ts, "<session_end>"))
    commit_intervals: list[dict[str, Any]] = []
    for (from_ts, from_label), (to_ts, to_label) in pairwise(boundaries):
        interval_wall, interval_active, interval_idle = _window_activity_breakdown(
            timestamps_sorted=timestamps,
            start_utc=from_ts,
            end_utc=to_ts,
            idle_threshold=idle_threshold,
        )
        commit_intervals.append(
            {
                "from_utc": from_ts.isoformat(),
                "to_utc": to_ts.isoformat(),
                "from_label": from_label,
                "to_label": to_label,
                "wall_minutes": round(interval_wall / 60.0, 2),
                "active_minutes": round(interval_active / 60.0, 2),
                "idle_minutes": round(interval_idle / 60.0, 2),
                "active_ratio": round(interval_active / interval_wall, 4)
                if interval_wall
                else None,
            }
        )

    git_commit_timing: dict[str, Any] | None = None
    if repo_root is not None and from_ref is not None and to_ref is not None:
        git_boundaries: list[tuple[datetime, str, str | None]] = [
            (analysis_start, "<analysis_start>", None)
        ]
        git_boundaries.extend(
            (commit.timestamp_utc, commit.subject, commit.sha[:7])
            for commit in git_commits_in_window
        )
        git_boundaries.append((analysis_end, "<analysis_end>", None))
        git_intervals: list[dict[str, Any]] = []
        for (from_ts, from_label, from_sha), (to_ts, to_label, to_sha) in pairwise(git_boundaries):
            interval_wall, interval_active, interval_idle = _window_activity_breakdown(
                timestamps_sorted=timestamps,
                start_utc=from_ts,
                end_utc=to_ts,
                idle_threshold=idle_threshold,
            )
            git_intervals.append(
                {
                    "from_utc": from_ts.isoformat(),
                    "to_utc": to_ts.isoformat(),
                    "from_sha_short": from_sha,
                    "from_subject": from_label,
                    "to_sha_short": to_sha,
                    "to_subject": to_label,
                    "wall_minutes": round(interval_wall / 60.0, 2),
                    "active_minutes": round(interval_active / 60.0, 2),
                    "idle_minutes": round(interval_idle / 60.0, 2),
                    "active_ratio": round(interval_active / interval_wall, 4)
                    if interval_wall
                    else None,
                }
            )
        git_commit_timing = {
            "from_ref": from_ref,
            "to_ref": to_ref,
            "analysis_start_utc": analysis_start.isoformat(),
            "analysis_end_utc": analysis_end.isoformat(),
            "commits_in_window": [commit.as_dict() for commit in git_commits_in_window],
            "intervals": git_intervals,
        }

    remediation_marker = "(remediation)"
    commit_next_action: dict[str, Any] | None = None
    if git_commit_timing is not None:
        intervals = git_commit_timing.get("intervals", [])
        commit_intervals_only = [
            interval
            for interval in intervals
            if interval.get("from_sha_short") is not None
            and interval.get("to_sha_short") is not None
        ]
        remediation_intervals = [
            interval
            for interval in commit_intervals_only
            if remediation_marker in (interval.get("to_subject") or "")
        ]
        non_remediation_intervals = [
            interval
            for interval in commit_intervals_only
            if remediation_marker not in (interval.get("to_subject") or "")
        ]
        remediation_cycle_starts = [
            interval
            for interval in remediation_intervals
            if remediation_marker not in (interval.get("from_subject") or "")
        ]

        def _empty_totals() -> dict[str, Any]:
            return {
                "intervals": 0,
                "wall_minutes": 0.0,
                "active_minutes": 0.0,
                "idle_minutes": 0.0,
            }

        def _add_to_totals(totals: dict[str, Any], row: dict[str, Any]) -> None:
            totals["intervals"] += 1
            totals["wall_minutes"] += float(row.get("wall_minutes") or 0.0)
            totals["active_minutes"] += float(row.get("active_minutes") or 0.0)
            totals["idle_minutes"] += float(row.get("idle_minutes") or 0.0)

        def _round_totals(totals: dict[str, Any]) -> dict[str, Any]:
            return {
                "intervals": int(totals.get("intervals", 0)),
                "wall_minutes": round(float(totals.get("wall_minutes", 0.0)), 2),
                "active_minutes": round(float(totals.get("active_minutes", 0.0)), 2),
                "idle_minutes": round(float(totals.get("idle_minutes", 0.0)), 2),
            }

        def _totals(rows: list[dict[str, Any]]) -> dict[str, Any]:
            return {
                "intervals": len(rows),
                "wall_minutes": round(sum(row.get("wall_minutes", 0.0) for row in rows), 2),
                "active_minutes": round(sum(row.get("active_minutes", 0.0) for row in rows), 2),
                "idle_minutes": round(sum(row.get("idle_minutes", 0.0) for row in rows), 2),
            }

        commit_milestones: dict[str, str | None] = {}
        milestone_assignment = {
            "strategy": (
                "Assign commits with exactly one M# mention to that milestone; "
                "forward-fill unlabeled commits from the most recent single-milestone commit; "
                "leave multi-milestone commits unassigned."
            ),
            "explicit_commits": 0,
            "inferred_commits": 0,
            "multi_milestone_commits": 0,
        }
        last_single: str | None = None
        for commit in git_commits_in_window:
            sha_short = commit.sha[:7]
            mentions = _milestone_mentions(commit.subject)
            if len(mentions) == 1:
                milestone = next(iter(mentions))
                commit_milestones[sha_short] = milestone
                last_single = milestone
                milestone_assignment["explicit_commits"] += 1
            elif len(mentions) == 0:
                commit_milestones[sha_short] = last_single
                if last_single is not None:
                    milestone_assignment["inferred_commits"] += 1
            else:
                commit_milestones[sha_short] = None
                milestone_assignment["multi_milestone_commits"] += 1

        by_milestone_raw: dict[str, dict[str, Any]] = {}

        def _get_bucket(milestone: str) -> dict[str, Any]:
            return by_milestone_raw.setdefault(
                milestone,
                {
                    "initial_totals": _empty_totals(),
                    "remediation_totals": _empty_totals(),
                    "total": _empty_totals(),
                    "by_remediation_pass": {},
                },
            )

        for interval in commit_intervals_only:
            to_sha = interval.get("to_sha_short")
            to_subject = interval.get("to_subject")
            milestone: str | None = (
                commit_milestones.get(to_sha) if isinstance(to_sha, str) else None
            )
            if milestone is None:
                milestone = _single_milestone(to_subject)
            milestone_key = milestone or "unassigned"
            bucket = _get_bucket(milestone_key)
            _add_to_totals(bucket["total"], interval)

            is_remediation_related = _is_remediation_related_subject(
                to_subject if isinstance(to_subject, str) else None
            )
            if is_remediation_related:
                _add_to_totals(bucket["remediation_totals"], interval)
                pass_label = "unknown"
                if milestone is not None and isinstance(to_subject, str):
                    passes = _remediation_passes_for_milestone(to_subject, milestone)
                    if len(passes) == 1:
                        pass_label = next(iter(passes))
                    elif len(passes) > 1:
                        pass_label = "multiple"
                pass_bucket = bucket["by_remediation_pass"].setdefault(pass_label, _empty_totals())
                _add_to_totals(pass_bucket, interval)
            else:
                _add_to_totals(bucket["initial_totals"], interval)

        by_milestone: dict[str, Any] = {}
        for key, bucket in by_milestone_raw.items():
            pass_totals = {
                pass_key: _round_totals(pass_bucket)
                for pass_key, pass_bucket in bucket["by_remediation_pass"].items()
            }
            by_milestone[key] = {
                "initial_totals": _round_totals(bucket["initial_totals"]),
                "remediation_totals": _round_totals(bucket["remediation_totals"]),
                "total": _round_totals(bucket["total"]),
                "by_remediation_pass": pass_totals,
            }

        remediation_cycle_starts_annotated: list[dict[str, Any]] = []
        remediation_cycle_starts_by_milestone: dict[str, list[dict[str, Any]]] = {}
        for interval in remediation_cycle_starts:
            to_sha = interval.get("to_sha_short")
            to_subject = interval.get("to_subject")
            milestone: str | None = (
                commit_milestones.get(to_sha) if isinstance(to_sha, str) else None
            )
            if milestone is None:
                milestone = _single_milestone(to_subject)
            pass_label: str | None = None
            if milestone is not None and isinstance(to_subject, str):
                passes = _remediation_passes_for_milestone(to_subject, milestone)
                if len(passes) == 1:
                    pass_label = next(iter(passes))
                elif len(passes) > 1:
                    pass_label = "multiple"
            annotated = dict(interval)
            annotated["milestone"] = milestone
            annotated["remediation_pass"] = pass_label
            remediation_cycle_starts_annotated.append(annotated)
            bucket_key = milestone or "unassigned"
            remediation_cycle_starts_by_milestone.setdefault(bucket_key, []).append(annotated)

        top_idle_intervals = sorted(
            commit_intervals_only, key=lambda row: row.get("idle_minutes", 0.0), reverse=True
        )[:10]
        commit_next_action = {
            "remediation_marker": remediation_marker,
            "commit_to_commit_totals": _totals(commit_intervals_only),
            "remediation_totals": _totals(remediation_intervals),
            "non_remediation_totals": _totals(non_remediation_intervals),
            "milestone_assignment": milestone_assignment,
            "by_milestone": by_milestone,
            "remediation_cycle_starts": remediation_cycle_starts,
            "remediation_cycle_starts_annotated": remediation_cycle_starts_annotated,
            "remediation_cycle_starts_by_milestone": remediation_cycle_starts_by_milestone,
            "top_idle_intervals": top_idle_intervals,
        }

    return {
        "idle_threshold_seconds": int(idle_threshold.total_seconds()),
        "analysis_start_utc": analysis_start.isoformat(),
        "analysis_end_utc": analysis_end.isoformat(),
        "first_event_utc": first_ts.isoformat(),
        "last_event_utc": last_ts.isoformat(),
        "wall_minutes": round(wall_seconds / 60.0, 2),
        "active_minutes": round(active_seconds / 60.0, 2),
        "idle_minutes": round(idle_seconds / 60.0, 2),
        "idle_gaps_top": idle_gap_rows,
        "commit_events": [ev.as_dict() for ev in commit_events],
        "commit_intervals": commit_intervals,
        "git_commit_timing": git_commit_timing,
        "commit_next_action": commit_next_action,
    }


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
    parser.add_argument(
        "--session-idle-threshold-seconds",
        type=int,
        default=300,
        help=(
            "Activity-gap threshold in seconds used to classify idle vs active time "
            "in session timing"
        ),
    )
    parser.add_argument(
        "--session-max-idle-gaps",
        type=int,
        default=10,
        help="Maximum number of largest idle gaps to include in session timing output",
    )
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
        payload["session_timing"] = _session_timing(
            session_file,
            repo_root=repo_root,
            from_ref=args.from_ref,
            to_ref=args.to_ref,
            start_utc=start_utc,
            end_utc=end_utc,
            idle_threshold=timedelta(seconds=max(0, args.session_idle_threshold_seconds)),
            max_idle_gaps=max(0, args.session_max_idle_gaps),
        )
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
