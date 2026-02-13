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
