from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


def _script_env() -> dict[str, str]:
    env = dict(os.environ)
    src_root = str(Path("src").resolve())
    current = env.get("PYTHONPATH", "").strip()
    env["PYTHONPATH"] = src_root if not current else f"{src_root}:{current}"
    return env


def test_release_stats_rollup_generates_range_payload() -> None:
    result = subprocess.run(
        [
            sys.executable,
            "scripts/release_stats_rollup.py",
            "--repo-root",
            ".",
            "--from-ref",
            "HEAD",
            "--to-ref",
            "HEAD",
        ],
        check=False,
        capture_output=True,
        text=True,
        env=_script_env(),
    )
    assert result.returncode == 0, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    assert payload["git"]["range"] == "HEAD..HEAD"
    assert payload["git"]["commits_in_range"] == 0
    assert payload["codebase"]["python_files"] >= 1
    assert payload["tests"]["test_files"] >= 1


def test_release_stats_rollup_parses_session_file(tmp_path: Path) -> None:
    session = tmp_path / "session.jsonl"
    session.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "timestamp": "2026-02-13T10:00:00.000Z",
                        "type": "event_msg",
                        "payload": {"type": "user_message", "message": "start"},
                    }
                ),
                json.dumps(
                    {
                        "timestamp": "2026-02-13T10:01:00.000Z",
                        "type": "response_item",
                        "payload": {"type": "function_call", "name": "exec_command"},
                    }
                ),
                json.dumps(
                    {
                        "timestamp": "2026-02-13T10:02:00.000Z",
                        "type": "response_item",
                        "payload": {"type": "function_call_output"},
                    }
                ),
                json.dumps(
                    {
                        "timestamp": "2026-02-13T10:03:00.000Z",
                        "type": "response_item",
                        "payload": {"type": "message", "role": "assistant"},
                    }
                ),
                "",
            ]
        ),
        encoding="utf-8",
    )
    output = tmp_path / "stats.json"
    result = subprocess.run(
        [
            sys.executable,
            "scripts/release_stats_rollup.py",
            "--repo-root",
            ".",
            "--from-ref",
            "HEAD",
            "--to-ref",
            "HEAD",
            "--session-file",
            str(session),
            "--output",
            str(output),
        ],
        check=False,
        capture_output=True,
        text=True,
        env=_script_env(),
    )
    assert result.returncode == 0, result.stdout + result.stderr
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["session"]["tool_calls"] == 1
    assert payload["session"]["tool_outputs"] == 1
    assert payload["session"]["assistant_messages"] == 1
    assert payload["session"]["user_messages"] == 1
    assert payload["session"]["tool_call_counts"]["exec_command"] == 1


def test_release_stats_rollup_applies_session_time_filters(tmp_path: Path) -> None:
    session = tmp_path / "session.jsonl"
    session.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "timestamp": "2026-02-13T09:59:00.000Z",
                        "type": "response_item",
                        "payload": {"type": "function_call", "name": "exec_command"},
                    }
                ),
                json.dumps(
                    {
                        "timestamp": "2026-02-13T10:00:00.000Z",
                        "type": "response_item",
                        "payload": {"type": "function_call", "name": "exec_command"},
                    }
                ),
                json.dumps(
                    {
                        "timestamp": "2026-02-13T10:01:00.000Z",
                        "type": "response_item",
                        "payload": {"type": "function_call_output"},
                    }
                ),
                json.dumps(
                    {
                        "timestamp": "2026-02-13T10:02:00.000Z",
                        "type": "response_item",
                        "payload": {"type": "message", "role": "assistant"},
                    }
                ),
                "",
            ]
        ),
        encoding="utf-8",
    )
    result = subprocess.run(
        [
            sys.executable,
            "scripts/release_stats_rollup.py",
            "--repo-root",
            ".",
            "--from-ref",
            "HEAD",
            "--to-ref",
            "HEAD",
            "--session-file",
            str(session),
            "--session-start-utc",
            "2026-02-13T10:00:00+00:00",
            "--session-end-utc",
            "2026-02-13T10:01:00+00:00",
        ],
        check=False,
        capture_output=True,
        text=True,
        env=_script_env(),
    )
    assert result.returncode == 0, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    assert payload["session"]["tool_calls"] == 1
    assert payload["session"]["tool_outputs"] == 1
    assert payload["session"]["assistant_messages"] == 0
    assert payload["session_filters"]["start_utc"] == "2026-02-13T10:00:00+00:00"
    assert payload["session_filters"]["end_utc"] == "2026-02-13T10:01:00+00:00"


def test_release_stats_rollup_extracts_commit_timing(tmp_path: Path) -> None:
    session = tmp_path / "session.jsonl"
    session.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "timestamp": "2026-02-13T10:00:00.000Z",
                        "type": "event_msg",
                        "payload": {"type": "user_message", "message": "start"},
                    }
                ),
                json.dumps(
                    {
                        "timestamp": "2026-02-13T10:01:00.000Z",
                        "type": "response_item",
                        "payload": {
                            "type": "function_call",
                            "name": "exec_command",
                            "arguments": json.dumps({"cmd": 'git commit -m "feat: first"'}),
                        },
                    }
                ),
                json.dumps(
                    {
                        "timestamp": "2026-02-13T10:02:00.000Z",
                        "type": "response_item",
                        "payload": {
                            "type": "function_call",
                            "name": "exec_command",
                            "arguments": json.dumps({"cmd": "rg -n test src/"}),
                        },
                    }
                ),
                json.dumps(
                    {
                        "timestamp": "2026-02-13T10:03:00.000Z",
                        "type": "response_item",
                        "payload": {"type": "message", "role": "assistant"},
                    }
                ),
                json.dumps(
                    {
                        "timestamp": "2026-02-13T10:11:00.000Z",
                        "type": "response_item",
                        "payload": {
                            "type": "function_call",
                            "name": "exec_command",
                            "arguments": json.dumps(
                                {"cmd": 'git commit -m "fix: second (remediation)"'}
                            ),
                        },
                    }
                ),
                json.dumps(
                    {
                        "timestamp": "2026-02-13T10:12:00.000Z",
                        "type": "response_item",
                        "payload": {"type": "message", "role": "assistant"},
                    }
                ),
                "",
            ]
        ),
        encoding="utf-8",
    )
    result = subprocess.run(
        [
            sys.executable,
            "scripts/release_stats_rollup.py",
            "--repo-root",
            ".",
            "--from-ref",
            "HEAD",
            "--to-ref",
            "HEAD",
            "--session-file",
            str(session),
            "--session-idle-threshold-seconds",
            "300",
            "--session-max-idle-gaps",
            "5",
        ],
        check=False,
        capture_output=True,
        text=True,
        env=_script_env(),
    )
    assert result.returncode == 0, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    commits = payload["session_timing"]["commit_events"]
    assert [row["subject"] for row in commits] == ["feat: first", "fix: second (remediation)"]
    assert payload["session_timing"]["wall_minutes"] == 12.0
    assert payload["session_timing"]["active_minutes"] == 4.0
    assert payload["session_timing"]["idle_minutes"] == 8.0
    assert payload["session_timing"]["idle_gaps_top"][0]["duration_minutes"] == 8.0
    assert payload["session_timing"]["idle_gaps_top"][0]["prev_commit_subject"] == "feat: first"
    assert (
        payload["session_timing"]["idle_gaps_top"][0]["next_commit_subject"]
        == "fix: second (remediation)"
    )
    intervals = payload["session_timing"]["commit_intervals"]
    assert intervals[0]["from_label"] == "<session_start>"
    assert intervals[0]["to_label"] == "feat: first"
    assert intervals[1]["from_label"] == "feat: first"
    assert intervals[1]["to_label"] == "fix: second (remediation)"
    assert intervals[2]["from_label"] == "fix: second (remediation)"
    assert intervals[2]["to_label"] == "<session_end>"
    assert intervals[1]["wall_minutes"] == 10.0
    assert intervals[1]["active_minutes"] == 2.0
    assert intervals[1]["idle_minutes"] == 8.0


def test_release_stats_rollup_computes_git_commit_timing(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True, text=True)
    subprocess.run(
        ["git", "config", "user.email", "test@example.com"],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "Test User"],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )

    file_path = repo / "file.txt"

    env = dict(os.environ)
    env["GIT_AUTHOR_DATE"] = "2026-02-13T10:00:00+00:00"
    env["GIT_COMMITTER_DATE"] = "2026-02-13T10:00:00+00:00"
    file_path.write_text("init\n", encoding="utf-8")
    subprocess.run(["git", "add", "file.txt"], cwd=repo, check=True, env=env)
    subprocess.run(
        ["git", "commit", "-m", "chore: init"],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
        env=env,
    )
    init_sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()

    env["GIT_AUTHOR_DATE"] = "2026-02-13T10:01:00+00:00"
    env["GIT_COMMITTER_DATE"] = "2026-02-13T10:01:00+00:00"
    file_path.write_text("first\n", encoding="utf-8")
    subprocess.run(["git", "add", "file.txt"], cwd=repo, check=True, env=env)
    subprocess.run(
        ["git", "commit", "-m", "feat: first"],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
        env=env,
    )

    env["GIT_AUTHOR_DATE"] = "2026-02-13T10:11:00+00:00"
    env["GIT_COMMITTER_DATE"] = "2026-02-13T10:11:00+00:00"
    file_path.write_text("second\n", encoding="utf-8")
    subprocess.run(["git", "add", "file.txt"], cwd=repo, check=True, env=env)
    subprocess.run(
        ["git", "commit", "-m", "fix: second (remediation)"],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
        env=env,
    )

    session = tmp_path / "session.jsonl"
    session.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "timestamp": "2026-02-13T10:00:00.000Z",
                        "type": "event_msg",
                        "payload": {"type": "user_message", "message": "start"},
                    }
                ),
                json.dumps(
                    {
                        "timestamp": "2026-02-13T10:01:00.000Z",
                        "type": "response_item",
                        "payload": {
                            "type": "function_call",
                            "name": "exec_command",
                            "arguments": json.dumps({"cmd": 'git commit -m "feat: first"'}),
                        },
                    }
                ),
                json.dumps(
                    {
                        "timestamp": "2026-02-13T10:02:00.000Z",
                        "type": "response_item",
                        "payload": {
                            "type": "function_call",
                            "name": "exec_command",
                            "arguments": json.dumps({"cmd": "rg -n test src/"}),
                        },
                    }
                ),
                json.dumps(
                    {
                        "timestamp": "2026-02-13T10:03:00.000Z",
                        "type": "response_item",
                        "payload": {"type": "message", "role": "assistant"},
                    }
                ),
                json.dumps(
                    {
                        "timestamp": "2026-02-13T10:11:00.000Z",
                        "type": "response_item",
                        "payload": {
                            "type": "function_call",
                            "name": "exec_command",
                            "arguments": json.dumps(
                                {"cmd": 'git commit -m "fix: second (remediation)"'}
                            ),
                        },
                    }
                ),
                json.dumps(
                    {
                        "timestamp": "2026-02-13T10:12:00.000Z",
                        "type": "response_item",
                        "payload": {"type": "message", "role": "assistant"},
                    }
                ),
                "",
            ]
        ),
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            sys.executable,
            "scripts/release_stats_rollup.py",
            "--repo-root",
            str(repo),
            "--from-ref",
            init_sha,
            "--to-ref",
            "HEAD",
            "--session-file",
            str(session),
            "--session-idle-threshold-seconds",
            "300",
        ],
        check=False,
        capture_output=True,
        text=True,
        env=_script_env(),
    )
    assert result.returncode == 0, result.stdout + result.stderr
    payload = json.loads(result.stdout)

    timing = payload["session_timing"]["git_commit_timing"]
    commits = timing["commits_in_window"]
    assert [row["subject"] for row in commits] == ["feat: first", "fix: second (remediation)"]
    remediation_interval = next(
        interval
        for interval in timing["intervals"]
        if interval["to_subject"] == "fix: second (remediation)"
    )
    assert remediation_interval["wall_minutes"] == 10.0
    assert remediation_interval["active_minutes"] == 2.0
    assert remediation_interval["idle_minutes"] == 8.0

    summary = payload["session_timing"]["commit_next_action"]
    assert summary["commit_to_commit_totals"]["intervals"] == 1
    assert summary["remediation_totals"]["intervals"] == 1
    assert summary["non_remediation_totals"]["intervals"] == 0
    assert summary["remediation_cycle_starts"][0]["to_subject"] == "fix: second (remediation)"
