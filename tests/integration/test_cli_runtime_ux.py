"""F6 cross-component CLI/runtime UX acceptance."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest
from click.testing import CliRunner

from shisad.cli import main as cli_main
from shisad.core.config import DaemonConfig
from shisad.ui import theme as theme_module
from shisad.ui.web import render_web_snapshot


def _config(tmp_path: Path) -> DaemonConfig:
    return DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "missing-control.sock",
        policy_path=tmp_path / "policy.yaml",
    )


@pytest.mark.parametrize("args", [["tui"], ["tui", "--plain"], ["tui", "--interactive"]])
def test_stopped_daemon_and_accessibility_controls_are_user_safe(
    args: list[str],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cli_main, "_get_config", lambda: _config(tmp_path))

    result = CliRunner().invoke(cli_main.cli, args)

    assert result.exit_code == 2
    assert "What failed: Could not connect to the shisad daemon." in result.output
    assert "What still works: config, help, and offline inspection commands." in result.output
    assert "Next action: shisad start --foreground" in result.output
    assert "Traceback" not in result.output


def _chromium_binary() -> Path | None:
    configured = os.environ.get("SHISAD_TEST_CHROMIUM", "").strip()
    if configured:
        return Path(configured)
    for candidate in (
        Path("/usr/bin/chromium"),
        Path("/usr/bin/chromium-browser"),
        Path("/usr/bin/google-chrome"),
    ):
        if candidate.is_file():
            return candidate
    cache = Path.home() / ".cache" / "ms-playwright"
    matches = sorted(
        cache.glob("chromium_headless_shell-*/chrome-headless-shell-linux64/chrome-headless-shell")
    )
    return matches[-1] if matches else None


def test_f6_web_snapshot_payload_executes_in_real_browser_dom(tmp_path: Path) -> None:
    chromium = _chromium_binary()
    if chromium is None:
        pytest.skip("actual local Chromium is not installed")
    hostile = '</script><script>document.body.dataset.pwned="yes"</script>&'
    posture = theme_module.resolve_ui_posture(
        theme_name="shisa-high-contrast",
        reduce_motion=True,
        environ={"TERM": "dumb"},
        isatty=False,
    )
    output = tmp_path / "snapshot.html"
    output.write_text(
        render_web_snapshot(
            {
                "sessions": [{"id": hostile}],
                "pending_actions": [],
                "alerts": [],
                "egress_events": [],
            },
            ui_posture=posture,
        ),
        encoding="utf-8",
    )

    completed = subprocess.run(
        [
            str(chromium),
            "--headless",
            "--no-sandbox",
            "--disable-gpu",
            "--dump-dom",
            output.as_uri(),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert completed.returncode == 0, completed.stderr
    rendered_hostile = (
        hostile.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', '\\"')
    )
    assert rendered_hostile in completed.stdout
    for section in ("pending", "alerts", "egress"):
        assert f'<pre id="{section}">[]</pre>' in completed.stdout
    assert 'data-pwned="yes"' not in completed.stdout
    assert 'data-reduce-motion="true"' in completed.stdout


@pytest.mark.skipif(sys.platform == "win32", reason="foreground signal contract is POSIX-only")
def test_foreground_sigint_has_no_duplicate_stop_or_bad_fd_noise(tmp_path: Path) -> None:
    runtime_dir = tmp_path / "run"
    workspace = tmp_path / "workspace"
    runtime_dir.mkdir()
    workspace.mkdir()
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        'version: "1"\n'
        "default_deny: false\n"
        "default_require_confirmation: false\n"
        "default_capabilities:\n"
        "  - file.read\n"
        "  - memory.read\n"
        "  - memory.write\n",
        encoding="utf-8",
    )
    socket_path = runtime_dir / "control.sock"
    env = {
        "PATH": os.environ.get("PATH", ""),
        "LANG": "C.UTF-8",
        "PYTHONUNBUFFERED": "1",
        "SHISAD_DATA_DIR": str(tmp_path / "data"),
        "SHISAD_SOCKET_PATH": str(socket_path),
        "SHISAD_POLICY_PATH": str(policy),
        "SHISAD_ASSISTANT_FS_ROOTS": json.dumps([str(workspace)]),
        "SHISAD_MEMORY_AUTO_EXTRACTION_ENABLED": "false",
        "SHISAD_WEB_SEARCH_ENABLED": "false",
        "SHISAD_BROWSER_ENABLED": "false",
        "SHISAD_MODEL_PLANNER_REMOTE_ENABLED": "false",
        "SHISAD_MODEL_EMBEDDINGS_REMOTE_ENABLED": "false",
        "SHISAD_MODEL_MONITOR_REMOTE_ENABLED": "false",
    }
    process = subprocess.Popen(
        [sys.executable, "-m", "shisad.cli.main", "start", "--foreground"],
        cwd=tmp_path,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        deadline = time.monotonic() + 20
        while process.poll() is None and not socket_path.exists() and time.monotonic() < deadline:
            time.sleep(0.1)
        assert process.poll() is None and socket_path.exists()
        process.send_signal(signal.SIGINT)
        output = process.communicate(timeout=20)[0]
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate(timeout=5)

    assert process.returncode == 0
    assert output.lower().count("shisad daemon stopped") == 1
    assert "Bad file descriptor" not in output
    assert "Exception ignored" not in output
    assert "Traceback" not in output
