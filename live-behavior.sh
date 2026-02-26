#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

if [[ -z "${UV_CACHE_DIR:-}" ]]; then
  export UV_CACHE_DIR="/tmp/uv-cache"
fi
mkdir -p "${UV_CACHE_DIR}"

usage() {
  cat <<'EOF'
Run shisad behavioral gates.

Usage:
  bash live-behavior.sh                 # deterministic + live-model suites (per-test output)
  bash live-behavior.sh --verbose       # very verbose test output + executed command echo
  bash live-behavior.sh --quiet         # compact dot output
  bash live-behavior.sh --behavioral    # deterministic behavioral suite only
  bash live-behavior.sh --contract      # deterministic live-daemon contract only
  bash live-behavior.sh --live-model    # live-model contract only (requires remote model config)
  bash live-behavior.sh --all           # deterministic + live-model suites
  bash live-behavior.sh --tool-matrix   # probe a *running* daemon (see docs/TOOL-STATUS.md)

Notes:
  - Default mode runs deterministic tests and attempts live-model tests when configured.
  - Default output shows each test as PASSED/FAILED.
  - Use --behavioral for deterministic-only execution.
EOF
}

want_behavioral=false
want_contract=false
want_live_model=false
want_tool_matrix=false
explicit_live_request=false
verbose=false
quiet=false

pytest_args=(-v -ra)

run_cmd() {
  if [[ "${verbose}" == true ]]; then
    printf '+ '
    printf '%q ' "$@"
    printf '\n'
  fi
  "$@"
}

while [[ "${#}" -gt 0 ]]; do
  case "${1}" in
    -h|--help)
      usage
      exit 0
      ;;
    -v|--verbose)
      verbose=true
      ;;
    -q|--quiet)
      quiet=true
      ;;
    --behavioral|--all)
      want_behavioral=true
      if [[ "${1}" == "--all" ]]; then
        want_live_model=true
        explicit_live_request=true
      fi
      ;;
    --contract)
      want_contract=true
      ;;
    --live-model)
      want_live_model=true
      explicit_live_request=true
      ;;
    --tool-matrix)
      want_tool_matrix=true
      ;;
    *)
      echo "Unknown option: ${1}" >&2
      echo >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

if [[ "${want_behavioral}" == false ]] \
  && [[ "${want_contract}" == false ]] \
  && [[ "${want_live_model}" == false ]] \
  && [[ "${want_tool_matrix}" == false ]]; then
  want_behavioral=true
  want_live_model=true
fi

if [[ "${verbose}" == true ]]; then
  pytest_args=(-vv -rA)
elif [[ "${quiet}" == true ]]; then
  pytest_args=(-q)
fi

if [[ "${want_behavioral}" == true ]]; then
  run_cmd uv run pytest tests/behavioral/ "${pytest_args[@]}"
fi

if [[ "${want_contract}" == true ]]; then
  run_cmd uv run pytest tests/behavioral/test_behavioral_contract.py "${pytest_args[@]}"
fi

if [[ "${want_live_model}" == true ]]; then
  live_prereq_error=""
  if [[ "${SHISAD_MODEL_REMOTE_ENABLED:-}" =~ ^(false|0|no)$ ]]; then
    live_prereq_error="SHISAD_MODEL_REMOTE_ENABLED is disabled."
  elif [[ "${SHISAD_MODEL_PLANNER_REMOTE_ENABLED:-}" =~ ^(false|0|no)$ ]]; then
    live_prereq_error="SHISAD_MODEL_PLANNER_REMOTE_ENABLED is disabled."
  elif [[ -z "${SHISAD_MODEL_PLANNER_API_KEY:-}" ]] \
    && [[ -z "${SHISAD_MODEL_API_KEY:-}" ]] \
    && [[ -z "${SHISA_API_KEY:-}" ]] \
    && [[ -z "${OPENAI_API_KEY:-}" ]] \
    && [[ -z "${OPENROUTER_API_KEY:-}" ]] \
    && [[ -z "${GEMINI_API_KEY:-}" ]]; then
    live_prereq_error="no API key env var found."
  fi

  if [[ -n "${live_prereq_error}" ]]; then
    if [[ "${explicit_live_request}" == true ]]; then
      echo "Refusing --live-model: ${live_prereq_error}" >&2
      if [[ "${live_prereq_error}" == "no API key env var found." ]]; then
        echo "Set one of: SHISAD_MODEL_PLANNER_API_KEY, SHISAD_MODEL_API_KEY, SHISA_API_KEY," >&2
        echo "OPENAI_API_KEY, OPENROUTER_API_KEY, GEMINI_API_KEY." >&2
      fi
      exit 2
    fi
    echo "Skipping live-model behavioral suite: ${live_prereq_error}" >&2
    if [[ "${live_prereq_error}" == "no API key env var found." ]]; then
      echo "Set API key env vars and rerun with --live-model to require live execution." >&2
    fi
  else
    # Auto-select OpenAI GPT-5.2 when OPENAI_API_KEY is available and no
    # explicit planner model/preset/base-url has been configured.  The Shisa
    # default model (14B) does not reliably emit OpenAI-format tool calls.
    live_env=(SHISAD_LIVE_MODEL_TESTS=1)
    if [[ -n "${OPENAI_API_KEY:-}" ]] \
      && [[ -z "${SHISAD_MODEL_PLANNER_PROVIDER_PRESET:-}" ]] \
      && [[ -z "${SHISAD_MODEL_PLANNER_BASE_URL:-}" ]] \
      && [[ -z "${SHISAD_MODEL_PLANNER_MODEL_ID:-}" ]]; then
      live_env+=(
        SHISAD_MODEL_PLANNER_PROVIDER_PRESET=openai_default
      )
    fi
    run_cmd env "${live_env[@]}" uv run pytest \
      tests/behavioral/test_behavioral_contract_live_model.py "${pytest_args[@]}"
  fi
fi

if [[ "${want_tool_matrix}" == true ]]; then
  run_cmd uv run python scripts/live_tool_matrix.py
fi
