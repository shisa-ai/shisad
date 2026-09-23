"""Runner shutdown exercises isolated process groups, never the live daemon."""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

_HARNESS = Path(__file__).resolve().parents[2] / "runner" / "harness.sh"


def _stop(
    tmp_path: Path, pid: int = 0, *, hung_rpc: bool = False
) -> subprocess.CompletedProcess[str]:
    binary = tmp_path / "bin"
    binary.mkdir()
    for name, body in {
        "tmux": "exit 0",
        "uv": "sleep 30" if hung_rpc else "exit 1",
    }.items():
        path = binary / name
        path.write_text(f"#!/bin/sh\n{body}\n")
        path.chmod(0o755)
    source = _HARNESS.read_text().split("_cmd_stop() {", 1)[1].split("\n_cmd_restart()", 1)[0]
    script = """
set -euo pipefail
_runner_env() { :; }
_preflight_socket_parent() { :; }
_runner_socket_path() { printf '%s' "$TEST_SOCKET"; }
_daemon_pid_path() { printf '%s.pid' "$TEST_SOCKET"; }
_tmux_session_name() { printf 'isolated-test'; }
_tmux() {
  case "$1" in
    has-session) test "$TEST_PID" != 0;;
    display-message) printf '%s' "$TEST_PID";;
    kill-session) :;;
  esac
}
_warn() { echo "$*" >&2; }
_die() { echo "$*" >&2; exit 1; }
"""
    return subprocess.run(
        ["bash"],
        input=f"{script}\n_cmd_stop() {{{source}\n_cmd_stop\n",
        env={
            **os.environ,
            "PATH": f"{binary}:{os.environ['PATH']}",
            "TEST_SOCKET": str(tmp_path / "daemon.sock"),
            "TEST_PID": str(pid),
        },
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )


def test_failed_stop_preserves_socket_without_owned_process(tmp_path: Path) -> None:
    socket = tmp_path / "daemon.sock"
    socket.touch()
    result = _stop(tmp_path)
    assert result.returncode != 0
    assert socket.exists()


@pytest.mark.parametrize("ignore_term", [False, True])
def test_stop_terminates_owned_group_before_cleanup(tmp_path: Path, ignore_term: bool) -> None:
    ready = tmp_path / "ready"
    code = (
        "import signal,time,pathlib; signal.signal(signal.SIGHUP, signal.SIG_IGN); "
        + ("signal.signal(signal.SIGTERM, signal.SIG_IGN); " if ignore_term else "")
        + f"pathlib.Path({str(ready)!r}).touch(); time.sleep(60)"
    )
    process = subprocess.Popen([sys.executable, "-c", code], start_new_session=True)
    try:
        deadline = time.monotonic() + 5
        while not ready.exists():
            assert time.monotonic() < deadline
            time.sleep(0.01)
        socket = tmp_path / "daemon.sock"
        socket.touch()
        result = _stop(tmp_path, process.pid)
        assert process.poll() is not None, result.stderr
        assert result.returncode == 0, result.stderr
        assert not socket.exists()
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
        process.wait()


def test_hung_stop_rpc_is_bounded_and_retains_unverified_socket(tmp_path: Path) -> None:
    socket = tmp_path / "daemon.sock"
    socket.touch()
    started = time.monotonic()
    result = _stop(tmp_path, hung_rpc=True)
    assert time.monotonic() - started < 12
    assert result.returncode != 0
    assert socket.exists()
