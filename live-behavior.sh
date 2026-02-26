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
  bash live-behavior.sh                 # deterministic behavioral suite (default)
  bash live-behavior.sh --verbose       # verbose test output + executed command echo
  bash live-behavior.sh --contract      # deterministic live-daemon contract only
  bash live-behavior.sh --live-model    # opt-in live-model contract (requires remote model config)
  bash live-behavior.sh --tool-matrix   # probe a *running* daemon (see docs/TOOL-STATUS.md)

Notes:
  - Default mode is deterministic and does not call remote model providers.
  - --live-model is intended for v0.3.4 model suitability evaluation; it is opt-in.
EOF
}

want_behavioral=false
want_contract=false
want_live_model=false
want_tool_matrix=false
verbose=false

pytest_args=(-q)

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
    --behavioral|--all)
      want_behavioral=true
      ;;
    --contract)
      want_contract=true
      ;;
    --live-model)
      want_live_model=true
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
fi

if [[ "${verbose}" == true ]]; then
  pytest_args=(-vv -rA)
fi

if [[ "${want_behavioral}" == true ]]; then
  run_cmd uv run pytest tests/behavioral/ "${pytest_args[@]}"
fi

if [[ "${want_contract}" == true ]]; then
  run_cmd uv run pytest tests/behavioral/test_behavioral_contract.py "${pytest_args[@]}"
fi

if [[ "${want_live_model}" == true ]]; then
  if [[ "${SHISAD_MODEL_REMOTE_ENABLED:-}" =~ ^(false|0|no)$ ]]; then
    echo "Refusing --live-model: SHISAD_MODEL_REMOTE_ENABLED is disabled." >&2
    exit 2
  fi
  if [[ "${SHISAD_MODEL_PLANNER_REMOTE_ENABLED:-}" =~ ^(false|0|no)$ ]]; then
    echo "Refusing --live-model: SHISAD_MODEL_PLANNER_REMOTE_ENABLED is disabled." >&2
    exit 2
  fi
  if [[ -z "${SHISAD_MODEL_PLANNER_API_KEY:-}" ]] \
    && [[ -z "${SHISAD_MODEL_API_KEY:-}" ]] \
    && [[ -z "${SHISA_API_KEY:-}" ]] \
    && [[ -z "${OPENAI_API_KEY:-}" ]] \
    && [[ -z "${OPENROUTER_API_KEY:-}" ]] \
    && [[ -z "${GEMINI_API_KEY:-}" ]]; then
    echo "Refusing --live-model: no API key env var found." >&2
    echo "Set one of: SHISAD_MODEL_PLANNER_API_KEY, SHISAD_MODEL_API_KEY, SHISA_API_KEY," >&2
    echo "OPENAI_API_KEY, OPENROUTER_API_KEY, GEMINI_API_KEY." >&2
    exit 2
  fi
  run_cmd env SHISAD_LIVE_MODEL_TESTS=1 uv run pytest \
    tests/behavioral/test_behavioral_contract_live_model.py "${pytest_args[@]}"
fi

if [[ "${want_tool_matrix}" == true ]]; then
  run_cmd uv run python scripts/live_tool_matrix.py
fi
