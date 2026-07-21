"""U43 typed child-process environment policy coverage."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from shisad.core.process_environment import (
    ChildEnvironmentProfile,
    build_child_environment,
    inspect_git_filters,
)

_POISONED_PARENT = {
    "PATH": "/safe/bin",
    "HOME": "/home/alice",
    "LANG": "C.UTF-8",
    "TERM": "xterm-256color",
    "SHISAD_LOG_LEVEL": "DEBUG",
    "SHISAD_MODEL_REMOTE_ENABLED": "true",
    "SSH_AUTH_SOCK": "/tmp/agent.sock",
    "OPENAI_API_KEY": "openai-secret",
    "ANTHROPIC_API_KEY": "anthropic-secret",
    "AWS_SECRET_ACCESS_KEY": "aws-secret",
    "HTTP_PROXY": "http://proxy.example",
    "NODE_OPTIONS": "--require=/tmp/poison.js",
    "PYTHONPATH": "/tmp/poison-python",
    "GIT_CONFIG_COUNT": "1",
    "GIT_ASKPASS": "/tmp/poison-askpass",
    "SSH_ASKPASS": "/tmp/poison-ssh-askpass",
    "BASH_FUNC_poison%%": "() { touch /tmp/poison; }",
    "UNRELATED_SECRET": "must-not-cross",
}


@pytest.mark.parametrize(
    ("profile", "required", "forbidden"),
    [
        (
            ChildEnvironmentProfile.SIDECAR,
            {
                "PATH",
                "LANG",
                "SHISAD_LOG_LEVEL",
                "SHISAD_MODEL_REMOTE_ENABLED",
                "OPENAI_API_KEY",
            },
            {"AWS_SECRET_ACCESS_KEY", "NODE_OPTIONS", "PYTHONPATH", "GIT_CONFIG_COUNT"},
        ),
        (
            ChildEnvironmentProfile.ISOLATION_CONTROL,
            {"PATH", "LANG"},
            {"HOME", "SSH_AUTH_SOCK", "ANTHROPIC_API_KEY", "NODE_OPTIONS"},
        ),
        (
            ChildEnvironmentProfile.SIGNATURE,
            {"PATH", "LANG"},
            {"HOME", "SSH_AUTH_SOCK", "ANTHROPIC_API_KEY", "SSH_ASKPASS"},
        ),
        (
            ChildEnvironmentProfile.SSH_FORWARD,
            {"PATH", "HOME", "LANG", "TERM", "SSH_AUTH_SOCK"},
            {"ANTHROPIC_API_KEY", "GIT_ASKPASS", "SSH_ASKPASS", "NODE_OPTIONS"},
        ),
        (
            ChildEnvironmentProfile.MSGVAULT,
            {"PATH", "HOME", "LANG"},
            {"ANTHROPIC_API_KEY", "SSH_AUTH_SOCK", "NODE_OPTIONS", "PYTHONPATH"},
        ),
        (
            ChildEnvironmentProfile.MCP_STDIO,
            {"PATH", "HOME", "LANG"},
            {"ANTHROPIC_API_KEY", "SSH_AUTH_SOCK", "NODE_OPTIONS", "PYTHONPATH"},
        ),
        (
            ChildEnvironmentProfile.CODING_AGENT,
            {
                "PATH",
                "HOME",
                "LANG",
                "TERM",
                "ANTHROPIC_API_KEY",
                "OPENAI_API_KEY",
                "AWS_SECRET_ACCESS_KEY",
                "HTTP_PROXY",
            },
            {"SSH_AUTH_SOCK", "NODE_OPTIONS", "PYTHONPATH", "GIT_CONFIG_COUNT"},
        ),
        (
            ChildEnvironmentProfile.GIT,
            {"PATH", "LANG"},
            {
                "HOME",
                "ANTHROPIC_API_KEY",
                "SSH_AUTH_SOCK",
                "NODE_OPTIONS",
                "GIT_CONFIG_COUNT",
                "GIT_ASKPASS",
            },
        ),
    ],
)
def test_f4c_child_environment_profiles_bound_poisoned_parent(
    profile: ChildEnvironmentProfile,
    required: set[str],
    forbidden: set[str],
) -> None:
    child = build_child_environment(profile, parent=_POISONED_PARENT)

    assert required <= child.keys()
    assert forbidden.isdisjoint(child)
    assert "BASH_FUNC_poison%%" not in child
    assert "UNRELATED_SECRET" not in child


def test_f4c_git_environment_sets_fixed_noninteractive_controls() -> None:
    child = build_child_environment(
        ChildEnvironmentProfile.GIT,
        parent=_POISONED_PARENT,
    )

    assert child["GIT_CONFIG_NOSYSTEM"] == "1"
    assert child["GIT_TERMINAL_PROMPT"] == "0"
    assert child["GIT_ATTR_NOSYSTEM"] == "1"
    assert child["GIT_PAGER"] == "cat"
    assert child["PAGER"] == "cat"


def test_f4c_mcp_explicit_override_is_scoped_to_that_child() -> None:
    child = build_child_environment(
        ChildEnvironmentProfile.MCP_STDIO,
        parent=_POISONED_PARENT,
        overrides={"MCP_VISIBLE_FLAG": "visible", "NODE_OPTIONS": "--configured-explicitly"},
    )

    assert child["MCP_VISIBLE_FLAG"] == "visible"
    assert child["NODE_OPTIONS"] == "--configured-explicitly"
    assert "UNRELATED_SECRET" not in child


def _init_globally_configured_filter_repo(
    tmp_path: Path,
) -> tuple[Path, Path, Path]:
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "-C", str(repo), "init"], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(repo), "config", "user.email", "test@example.com"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(repo), "config", "user.name", "Test User"],
        check=True,
    )
    (repo / ".gitattributes").write_text("payload.txt filter=poison\n", encoding="utf-8")
    (repo / "payload.txt").write_text("payload\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    subprocess.run(
        ["git", "-C", str(repo), "commit", "-m", "init"],
        check=True,
        capture_output=True,
    )

    marker = tmp_path / "filter.marker"
    helper = tmp_path / "filter-helper.py"
    helper.write_text(
        f"#!{sys.executable}\nfrom pathlib import Path\nPath({str(marker)!r}).touch()\n",
        encoding="utf-8",
    )
    helper.chmod(0o755)
    home = tmp_path / "home"
    home.mkdir()
    global_config = home / ".gitconfig"
    subprocess.run(
        ["git", "config", "--file", str(global_config), "filter.poison.clean", str(helper)],
        check=True,
    )
    subprocess.run(
        ["git", "config", "--file", str(global_config), "filter.poison.required", "true"],
        check=True,
    )
    return repo, home, marker


@pytest.mark.skipif(os.name != "posix", reason="executable filter fixture is POSIX")
def test_f4c_filter_inspection_detects_required_global_driver_without_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo, home, marker = _init_globally_configured_filter_repo(tmp_path)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(tmp_path / "ambient-global-config"))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "filter.poison.required")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", "false")

    inspection = inspect_git_filters(repo)

    assert inspection.active_drivers == ("poison",)
    assert inspection.required_executable_drivers == ("poison",)
    assert not marker.exists()


@pytest.mark.skipif(os.name != "posix", reason="executable filter fixture is POSIX")
def test_f4c_filter_inspection_honors_local_required_override(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo, home, marker = _init_globally_configured_filter_repo(tmp_path)
    subprocess.run(
        ["git", "-C", str(repo), "config", "filter.poison.required", "false"],
        check=True,
    )
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)

    inspection = inspect_git_filters(repo)

    assert inspection.active_drivers == ("poison",)
    assert inspection.required_executable_drivers == ()
    assert not marker.exists()
