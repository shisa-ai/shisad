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
    assert "uv run shisad" in harness_text
    assert "RUNNER_INHERIT_SHISAD_ENV" in harness_text
    assert "SHISAD_DISCORD_ENABLED" in harness_text
    assert "tmux" in harness_text
    assert "Operator Runbook" in runbook_text
    assert "conda" in readme_text
    assert "mamba" in readme_text
    assert "bash runner/harness.sh shisad status" in readme_text


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


def test_f3_harness_bootstrap_leaves_data_root_for_daemon_admission(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    env = {k: v for k, v in os.environ.items()}
    env.update(
        {
            "RUNNER_INHERIT_SHISAD_ENV": "1",
            "RUNNER_TMUX_SOCKET_NAME": "f3-bootstrap",
            "RUNNER_TMUX_SESSION_NAME": "f3-bootstrap",
            "SHISAD_DATA_DIR": str(data_dir),
            "SHISAD_SOCKET_PATH": str(tmp_path / "control.sock"),
            "SHISAD_POLICY_PATH": str(tmp_path / "policy.yaml"),
        }
    )
    result = subprocess.run(
        [
            "bash",
            "-c",
            "source runner/harness.sh >/dev/null\numask 0002\n"
            "_ensure_bootstrap_dirs\n_daemon_log_path",
        ],
        capture_output=True,
        text=True,
        cwd=str(Path.cwd()),
        env=env,
    )

    assert result.returncode == 0, result.stderr
    log_path = Path(result.stdout.strip().splitlines()[-1])
    assert not data_dir.exists()
    assert log_path.parent != data_dir
    assert stat.S_IMODE(log_path.parent.stat().st_mode) == 0o700


def test_f3_harness_missing_policy_overlap_fails_before_authority_parent_creation(
    tmp_path: Path,
) -> None:
    cases = [
        (
            tmp_path / "beneath-data" / "data",
            tmp_path / "control.sock",
            tmp_path / "beneath-data" / "data" / "config" / "policy.yaml",
            tmp_path / "beneath-data" / "data",
        ),
        (
            tmp_path / "shared-parent" / "data",
            tmp_path / "shared-parent" / "control.sock",
            tmp_path / "shared-parent" / "policy.yaml",
            tmp_path / "shared-parent",
        ),
        (
            tmp_path / "socket-path-data",
            tmp_path / "socket-path" / "control.sock",
            tmp_path / "socket-path" / "control.sock" / "config" / "policy.yaml",
            tmp_path / "socket-path",
        ),
        (
            tmp_path / "socket-parent-data",
            tmp_path / "absent-socket-parent" / "control.sock",
            tmp_path / "absent-socket-parent" / "policies" / "policy.yaml",
            tmp_path / "absent-socket-parent",
        ),
    ]
    for index, (data_dir, socket_path, policy_path, forbidden_parent) in enumerate(cases):
        env = {k: v for k, v in os.environ.items()}
        env.update(
            {
                "RUNNER_INHERIT_SHISAD_ENV": "1",
                "RUNNER_TMUX_SOCKET_NAME": f"f3-policy-{index}",
                "RUNNER_TMUX_SESSION_NAME": f"f3-policy-{index}",
                "SHISAD_DATA_DIR": str(data_dir),
                "SHISAD_SOCKET_PATH": str(socket_path),
                "SHISAD_POLICY_PATH": str(policy_path),
            }
        )
        result = subprocess.run(
            [
                "bash",
                "-c",
                "source runner/harness.sh >/dev/null\n"
                "_ensure_bootstrap_dirs\n_ensure_policy_file",
            ],
            capture_output=True,
            text=True,
            cwd=str(Path.cwd()),
            env=env,
        )

        assert result.returncode != 0
        assert "policy" in result.stderr
        assert not forbidden_parent.exists()


def test_f3_harness_bootstraps_disjoint_policy_parent_owner_only(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    policy_path = tmp_path / "policy-parent" / "policy.yaml"
    env = {k: v for k, v in os.environ.items()}
    env.update(
        {
            "RUNNER_INHERIT_SHISAD_ENV": "1",
            "RUNNER_TMUX_SOCKET_NAME": "f3-policy-disjoint",
            "RUNNER_TMUX_SESSION_NAME": "f3-policy-disjoint",
            "SHISAD_DATA_DIR": str(data_dir),
            "SHISAD_SOCKET_PATH": str(tmp_path / "control.sock"),
            "SHISAD_POLICY_PATH": str(policy_path),
        }
    )
    result = subprocess.run(
        [
            "bash",
            "-c",
            "source runner/harness.sh >/dev/null\numask 0002\n"
            "_ensure_bootstrap_dirs\n_ensure_policy_file",
        ],
        capture_output=True,
        text=True,
        cwd=str(Path.cwd()),
        env=env,
    )

    assert result.returncode == 0, result.stderr
    assert not data_dir.exists()
    assert stat.S_IMODE(policy_path.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(policy_path.stat().st_mode) == 0o600


def test_f3_harness_default_policy_uses_runner_state() -> None:
    env = {
        k: v
        for k, v in os.environ.items()
        if not k.startswith("SHISAD_") and not k.startswith("RUNNER_TMUX_")
    }
    env.update(
        {
            "RUNNER_TMUX_SOCKET_NAME": "f3-default-policy",
            "RUNNER_TMUX_SESSION_NAME": "f3-default-policy",
        }
    )
    result = subprocess.run(
        ["bash", "runner/harness.sh", "env"],
        capture_output=True,
        text=True,
        cwd=str(Path.cwd()),
        env=env,
    )

    assert result.returncode == 0, result.stderr
    values = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
    assert Path(values["SHISAD_POLICY_PATH"]).parent == Path(values["DAEMON_LOG"]).parent


def test_f3_harness_runner_state_key_is_injective() -> None:
    first = _harness_env(
        {
            "RUNNER_INHERIT_SHISAD_ENV": "1",
            "RUNNER_TMUX_SOCKET_NAME": "a--b",
            "RUNNER_TMUX_SESSION_NAME": "c",
        }
    )
    second = _harness_env(
        {
            "RUNNER_INHERIT_SHISAD_ENV": "1",
            "RUNNER_TMUX_SOCKET_NAME": "a",
            "RUNNER_TMUX_SESSION_NAME": "b--c",
        }
    )

    assert first["DAEMON_LOG"] != second["DAEMON_LOG"]
    assert first["DAEMON_PID"] != second["DAEMON_PID"]


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
