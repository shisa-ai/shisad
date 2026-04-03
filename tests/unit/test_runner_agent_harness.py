"""Repo guardrails and logic tests for the checked-in runner harness.

The harness is the canonical dev launcher for shisad: it manages env isolation,
secret loading, policy bootstrapping, and daemon lifecycle.
"""

from __future__ import annotations

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
