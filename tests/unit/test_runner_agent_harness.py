"""Repo guardrails and logic tests for the checked-in runner harness.

The harness is the canonical dev launcher for shisad: it manages env isolation,
secret loading, policy bootstrapping, and daemon lifecycle.
"""

from __future__ import annotations

import os
import stat
import subprocess
import tempfile
from pathlib import Path

# ---------------------------------------------------------------------------
# File-existence / documentation smoke tests
# ---------------------------------------------------------------------------


def test_runner_harness_files_exist_and_are_documented() -> None:
    readme = Path("runner/README.md")
    skill = Path("runner/SKILL.md")
    harness = Path("runner/harness.sh")
    env_example = Path("runner/.env.example")
    runbook = Path("runner/RUNBOOK.md")
    entrypoint = Path("runner/daemon_entrypoint.sh")
    policy_template = Path("runner/policy.default.yaml")

    assert readme.exists()
    assert skill.exists()
    assert harness.exists()
    assert env_example.exists()
    assert runbook.exists()
    assert entrypoint.exists()
    assert policy_template.exists()

    # RUNBOOK must be a real file, not a symlink.
    assert not runbook.is_symlink(), "RUNBOOK.md should not be a symlink"

    readme_text = readme.read_text(encoding="utf-8")
    skill_text = skill.read_text(encoding="utf-8")
    harness_text = harness.read_text(encoding="utf-8")
    runbook_text = runbook.read_text(encoding="utf-8")

    assert "runner/harness.sh" in readme_text
    assert "runner/harness.sh" in skill_text
    assert "uv --no-config run --frozen --python 3.12 shisad" in harness_text
    assert "RUNNER_INHERIT_SHISAD_ENV" in harness_text
    assert "SHISAD_DISCORD_ENABLED" in harness_text
    assert "tmux" in harness_text
    assert "Operator Runbook" in runbook_text
    assert "conda" in readme_text
    assert "mamba" in readme_text
    assert "bash runner/harness.sh shisad status" in readme_text


def test_runner_uv_calls_are_lock_and_interpreter_isolated() -> None:
    expected_prefix = "uv --no-config run --frozen --python 3.12"
    for path in (
        Path("runner/harness.sh"),
        Path("runner/daemon_entrypoint.sh"),
    ):
        text = path.read_text(encoding="utf-8")
        occurrences = text.count("uv --no-config run")
        assert occurrences > 0
        assert text.count(expected_prefix) == occurrences, f"{path} has an unisolated uv run call"


def test_gh50_manual_socket_docs_require_absolute_xdg_runtime_dir() -> None:
    snippet_paths = [
        Path("README.md"),
        Path("docs/DEPLOY.md"),
        Path("docs/ENV-VARS.md"),
        Path("docs/2FA.md"),
    ]
    for path in snippet_paths:
        text = path.read_text(encoding="utf-8")
        assert 'case "${XDG_RUNTIME_DIR:-}" in' in text
        assert '[ "${XDG_RUNTIME_DIR}" = /* ]' not in text

    prose_paths = [
        Path("docs/DEPLOY.md"),
        Path("docs/ENV-VARS.md"),
        Path("runner/SKILL.md"),
    ]
    for path in prose_paths:
        text = path.read_text(encoding="utf-8")
        assert "XDG_RUNTIME_DIR` is an absolute path" in text


def test_runner_defaults_are_version_agnostic() -> None:
    """Runner defaults must not contain milestone-specific names."""
    files = [
        "runner/harness.sh",
        "runner/.env.example",
        "runner/SKILL.md",
        "runner/README.md",
    ]
    for path in files:
        text = Path(path).read_text(encoding="utf-8")
        assert "shisad-m5" not in text, f"{path} still contains 'shisad-m5'"


def test_run_sh_is_thin_shim() -> None:
    """run.sh must delegate to runner/harness.sh, not duplicate env logic."""
    run_sh = Path("run.sh")
    assert run_sh.exists()
    text = run_sh.read_text(encoding="utf-8")

    assert "runner/harness.sh" in text
    # Must not contain duplicated env defaults.
    assert "SHISAD_DATA_DIR" not in text
    assert "SHISAD_POLICY_PATH" not in text


# ---------------------------------------------------------------------------
# Policy template tests
# ---------------------------------------------------------------------------


def test_policy_template_is_valid_yaml() -> None:
    """runner/policy.default.yaml must parse as valid YAML."""
    import yaml  # type: ignore[import-untyped]

    template = Path("runner/policy.default.yaml")
    data = yaml.safe_load(template.read_text(encoding="utf-8"))

    assert data["version"] == "1"
    assert isinstance(data["default_capabilities"], list)
    assert isinstance(data["tools"], dict)
    caps = data["default_capabilities"]
    assert "memory.read" in caps
    assert "memory.write" in caps
    assert "message.send" in caps
    assert "email.read" in caps


def test_policy_template_tools_use_dotted_names() -> None:
    """Tool names in the policy template should use dotted form."""
    import yaml  # type: ignore[import-untyped]

    template = Path("runner/policy.default.yaml")
    data = yaml.safe_load(template.read_text(encoding="utf-8"))

    for tool_name in data["tools"]:
        if tool_name == "report_anomaly":
            continue
        assert "." in tool_name or "_" not in tool_name, (
            f"tool '{tool_name}' should use dotted form"
        )


# ---------------------------------------------------------------------------
# Gitignore guardrails
# ---------------------------------------------------------------------------


def test_runner_env_is_gitignored() -> None:
    gitignore = Path(".gitignore").read_text(encoding="utf-8")
    assert "runner/.env" in gitignore


# ---------------------------------------------------------------------------
# Env-file parser tests (via runner/test_parse_env.sh helper)
# ---------------------------------------------------------------------------


def _run_parser(env_content: str) -> dict[str, str]:
    """Write a temp .env and run the bash parser helper."""
    with tempfile.NamedTemporaryFile(
        mode="w",
        suffix=".env",
        delete=False,
    ) as f:
        f.write(env_content)
        env_path = f.name

    result = subprocess.run(
        ["bash", "runner/test_parse_env.sh", env_path],
        capture_output=True,
        text=True,
        cwd=str(Path.cwd()),
    )
    out: dict[str, str] = {}
    for line in result.stdout.strip().splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            out[k] = v
    return out


def test_dotenv_parser_basic_key_value() -> None:
    result = _run_parser("TEST_FOO=bar\nTEST_BAZ=qux\n")
    assert result["TEST_FOO"] == "bar"
    assert result["TEST_BAZ"] == "qux"


def test_dotenv_parser_strips_quotes() -> None:
    result = _run_parser("TEST_DQ=\"double quoted\"\nTEST_SQ='single quoted'\nTEST_NQ=no quotes\n")
    assert result["TEST_DQ"] == "double quoted"
    assert result["TEST_SQ"] == "single quoted"
    assert result["TEST_NQ"] == "no quotes"


def test_dotenv_parser_handles_export_prefix() -> None:
    result = _run_parser("export TEST_EXP=exported_value\n")
    assert result["TEST_EXP"] == "exported_value"


def test_dotenv_parser_skips_comments_and_blanks() -> None:
    result = _run_parser("# This is a comment\n\n   \nTEST_REAL=value\n# Another comment\n")
    assert result == {"TEST_REAL": "value"}


def test_dotenv_parser_rejects_invalid_keys() -> None:
    result = _run_parser("123BAD=nope\nTEST_GOOD=yes\nbad-key=nope\n")
    assert "123BAD" not in result
    assert "bad-key" not in result
    assert result["TEST_GOOD"] == "yes"


# ---------------------------------------------------------------------------
# Harness integration tests (exercise harness.sh env command directly)
# ---------------------------------------------------------------------------


def _harness_env(
    extra_env: dict[str, str] | None = None,
) -> dict[str, str]:
    """Run ``bash runner/harness.sh env`` and return the output as a dict."""
    import os

    env = {k: v for k, v in os.environ.items()}
    if extra_env:
        env.update(extra_env)

    result = subprocess.run(
        ["bash", "runner/harness.sh", "env"],
        capture_output=True,
        text=True,
        cwd=str(Path.cwd()),
        env=env,
    )
    assert result.returncode == 0, result.stderr
    out: dict[str, str] = {}
    for line in result.stdout.strip().splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            out[k] = v
    return out


def test_harness_env_preserves_active_project_interpreter(tmp_path: Path) -> None:
    """Ambient uv controls must not replace Python or modify the lock."""
    project_python = Path(".venv/bin/python")
    lock_path = Path("uv.lock")
    lock_before = lock_path.read_bytes()
    uv_config = tmp_path / "uv.toml"
    uv_config.write_text(
        'exclude-newer = "2099-01-01T00:00:00Z"\n',
        encoding="utf-8",
    )
    before = subprocess.run(
        [str(project_python), "-c", "import platform; print(platform.python_version())"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()

    _harness_env(
        {
            "UV_CONFIG_FILE": str(uv_config),
            "UV_EXCLUDE_NEWER": "1970-01-01T00:00:00Z",
            "UV_PYTHON": str(tmp_path / "missing-python"),
        }
    )

    after = subprocess.run(
        [str(project_python), "-c", "import platform; print(platform.python_version())"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    assert after == before
    assert lock_path.read_bytes() == lock_before


def test_harness_env_file_survives_default_clear() -> None:
    """SHISAD_ENV_FILE must be loaded even when env clearing is active."""
    with tempfile.NamedTemporaryFile(
        mode="w",
        suffix=".env",
        delete=False,
    ) as f:
        f.write("SHISAD_DATA_DIR=/tmp/shisad-envfile-test\n")
        env_path = f.name

    result = _harness_env({"SHISAD_ENV_FILE": env_path})
    assert result["SHISAD_DATA_DIR"] == "/tmp/shisad-envfile-test"


def test_harness_tmux_socket_matches_session_default() -> None:
    """Default tmux socket and session should both be shisad-dev."""
    result = _harness_env()
    assert result["RUNNER_TMUX_SOCKET_NAME"] == "shisad-dev"
    assert result["RUNNER_TMUX_SESSION_NAME"] == "shisad-dev"


def test_gh50_harness_socket_matches_xdg_daemon_default(tmp_path: Path) -> None:
    runtime_dir = tmp_path / "runtime"
    result = _harness_env({"XDG_RUNTIME_DIR": str(runtime_dir)})

    assert result["SHISAD_SOCKET_PATH"] == str(runtime_dir / "shisad" / "control.sock")


def test_gh50_harness_rejects_symlinked_default_socket_dir(tmp_path: Path) -> None:
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir()
    runtime_dir.chmod(0o700)
    target = tmp_path / "target"
    target.mkdir()
    (runtime_dir / "shisad").symlink_to(target, target_is_directory=True)
    env = {k: v for k, v in os.environ.items() if not k.startswith("SHISAD_")}
    env["XDG_RUNTIME_DIR"] = str(runtime_dir)

    result = subprocess.run(
        ["bash", "runner/harness.sh", "shisad", "status"],
        capture_output=True,
        text=True,
        cwd=str(Path.cwd()),
        env=env,
    )

    assert result.returncode != 0
    assert "unsafe socket directory" in result.stderr
    assert "symlink" in result.stderr


def test_gh50_harness_direct_rpc_helpers_preflight_default_socket_dir(
    tmp_path: Path,
) -> None:
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir()
    runtime_dir.chmod(0o700)
    target = tmp_path / "target"
    target.mkdir()
    (runtime_dir / "shisad").symlink_to(target, target_is_directory=True)
    env = {k: v for k, v in os.environ.items() if not k.startswith("SHISAD_")}
    env["XDG_RUNTIME_DIR"] = str(runtime_dir)

    commands = [
        ["bash", "runner/harness.sh", "events"],
        ["bash", "runner/harness.sh", "session", "new"],
        ["bash", "runner/harness.sh", "session", "say", "session-1", "hello"],
    ]
    for command in commands:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            cwd=str(Path.cwd()),
            env=env,
        )

        assert result.returncode != 0
        assert "unsafe socket directory" in result.stderr
        assert "symlink" in result.stderr


def test_gh50_harness_client_preflight_rejects_world_writable_socket_dir(
    tmp_path: Path,
) -> None:
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir()
    runtime_dir.chmod(0o700)
    socket_dir = runtime_dir / "shisad"
    socket_dir.mkdir()
    socket_dir.chmod(0o777)
    (socket_dir / "control.sock").write_text("spoof", encoding="utf-8")
    env = {k: v for k, v in os.environ.items() if not k.startswith("SHISAD_")}
    env["XDG_RUNTIME_DIR"] = str(runtime_dir)

    for command in [
        ["bash", "runner/harness.sh", "shisad", "status"],
        ["bash", "runner/harness.sh", "start", "--no-debug"],
    ]:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            cwd=str(Path.cwd()),
            env=env,
        )

        assert result.returncode != 0
        assert "unsafe socket directory" in result.stderr
        assert "mode" in result.stderr
        assert stat.S_IMODE(socket_dir.stat().st_mode) == 0o777


def test_gh50_harness_ignores_relative_xdg_runtime_dir() -> None:
    result = _harness_env({"XDG_RUNTIME_DIR": "relative-runtime"})

    assert result["SHISAD_SOCKET_PATH"] == f"/tmp/shisad-{os.getuid()}/control.sock"


def test_gh50_harness_socket_falls_back_to_user_tmp_default() -> None:
    env = {k: v for k, v in os.environ.items() if k != "XDG_RUNTIME_DIR"}
    result = subprocess.run(
        ["bash", "runner/harness.sh", "env"],
        capture_output=True,
        text=True,
        cwd=str(Path.cwd()),
        env=env,
    )
    assert result.returncode == 0, result.stderr
    output = result.stdout

    assert f"SHISAD_SOCKET_PATH=/tmp/shisad-{os.getuid()}/control.sock" in output
    assert "/run/shisad" not in output
