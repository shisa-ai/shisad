#!/usr/bin/env bash
set -euo pipefail

# Test helper: sources the harness env-parser and prints exported TEST_* vars.
# Usage: bash runner/test_parse_env.sh <env-file-path>
#
# This script is used by tests/unit/test_runner_agent_harness.py to exercise
# the dotenv parser without embedding bash inside Python f-strings.

RUNNER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${RUNNER_DIR}/.." && pwd)"

_warn() { printf '%s\n' "warning: $*" >&2; }
_die() { printf '%s\n' "error: $*" >&2; exit 1; }

# Source just the parser function from harness.sh.
# We re-declare it here to avoid running main().
_parse_env_file() {
  local path="$1"
  local label="${2:-${path}}"

  if [[ ! -f "${path}" ]]; then
    return 0
  fi

  while IFS= read -r line || [[ -n "${line}" ]]; do
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line%"${line##*[![:space:]]}"}"
    [[ -z "${line}" ]] && continue
    [[ "${line}" == \#* ]] && continue

    if [[ "${line}" == export\ * ]]; then
      line="${line#export }"
      line="${line#"${line%%[![:space:]]*}"}"
    fi

    if [[ "${line}" != *=* ]]; then
      _warn "ignoring invalid ${label} line (no '='): ${line}"
      continue
    fi

    key="${line%%=*}"
    val="${line#*=}"

    if ! [[ "${key}" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
      _warn "ignoring invalid ${label} key: ${key}"
      continue
    fi

    if [[ "${val}" =~ ^\".*\"$ ]]; then
      val="${val:1:-1}"
    elif [[ "${val}" =~ ^\'.*\'$ ]]; then
      val="${val:1:-1}"
    fi

    export "${key}=${val}"
  done <"${path}"
}

env_file="${1:?usage: bash runner/test_parse_env.sh <env-file-path>}"
_parse_env_file "${env_file}" "test"

# Print all TEST_ prefixed vars for inspection.
env | grep '^TEST_' | sort || true
