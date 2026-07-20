"""U41 runner/runtime provider preflight parity tests."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_HARNESS = _REPO_ROOT / "runner" / "harness.sh"


def _run_preflight(extra_env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    source = _HARNESS.read_text(encoding="utf-8")
    function = source.split("_preflight_planner_credential() {", 1)[1].split(
        "\n\n_runner_env() {", 1
    )[0]
    source = (
        "set -euo pipefail\n"
        "_warn() { printf '%s\\n' \"warning: $*\" >&2; }\n"
        "_die() { printf '%s\\n' \"error: $*\" >&2; exit 1; }\n"
        f"_preflight_planner_credential() {{{function}\n"
    )
    env = {
        "PATH": os.environ.get("PATH", ""),
        "SHISAD_MODEL_PLANNER_PROVIDER_PRESET": "openai_default",
        "SHISAD_MODEL_PLANNER_REMOTE_ENABLED": "true",
        **extra_env,
    }
    return subprocess.run(
        ["bash"],
        input=f"{source}\n_preflight_planner_credential\n",
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def test_u41_gh90_explicit_planner_route_key_precedes_preset_key() -> None:
    result = _run_preflight(
        {
            "SHISAD_MODEL_PLANNER_BASE_URL": "https://provider.example/v1",
            "SHISAD_MODEL_PLANNER_API_KEY": "route-placeholder",
        }
    )

    assert result.returncode == 0, result.stderr
    assert "No API key found" not in result.stderr


def test_u41_gh90_global_model_key_is_accepted_before_preset_fallback() -> None:
    result = _run_preflight({"SHISAD_MODEL_API_KEY": "global-placeholder"})

    assert result.returncode == 0, result.stderr
    assert "required for planner preset" not in result.stderr
