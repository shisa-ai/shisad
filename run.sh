#!/usr/bin/env bash
set -euo pipefail

# Local helper for M5/bootstrap daemon runs.
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

export SHISAD_DATA_DIR="${SHISAD_DATA_DIR:-$ROOT_DIR/.local/shisad-m5}"
export SHISAD_SOCKET_PATH="${SHISAD_SOCKET_PATH:-/tmp/shisad-m5.sock}"
export SHISAD_POLICY_PATH="${SHISAD_POLICY_PATH:-$ROOT_DIR/.local/policy.yaml}"
export SHISAD_LOG_LEVEL="${SHISAD_LOG_LEVEL:-INFO}"
export SHISAD_CODING_REPO_ROOT="${SHISAD_CODING_REPO_ROOT:-$ROOT_DIR}"
export SHISAD_ASSISTANT_FS_ROOTS="${SHISAD_ASSISTANT_FS_ROOTS:-[\"$ROOT_DIR\"]}"
export SHISAD_CODING_AGENT_DEFAULT_PREFERENCE="${SHISAD_CODING_AGENT_DEFAULT_PREFERENCE:-[\"codex\",\"claude\"]}"
export SHISAD_CODING_AGENT_DEFAULT_FALLBACKS="${SHISAD_CODING_AGENT_DEFAULT_FALLBACKS:-[\"claude\"]}"
export SHISAD_CODING_AGENT_TIMEOUT_SECONDS="${SHISAD_CODING_AGENT_TIMEOUT_SECONDS:-1800}"

export SHISAD_MODEL_REMOTE_ENABLED="${SHISAD_MODEL_REMOTE_ENABLED:-false}"
export SHISAD_MODEL_PLANNER_REMOTE_ENABLED="${SHISAD_MODEL_PLANNER_REMOTE_ENABLED:-true}"
export SHISAD_MODEL_EMBEDDINGS_REMOTE_ENABLED="${SHISAD_MODEL_EMBEDDINGS_REMOTE_ENABLED:-false}"
export SHISAD_MODEL_MONITOR_REMOTE_ENABLED="${SHISAD_MODEL_MONITOR_REMOTE_ENABLED:-false}"

export SHISAD_MODEL_PLANNER_PROVIDER_PRESET="${SHISAD_MODEL_PLANNER_PROVIDER_PRESET:-openai_default}"
export SHISAD_MODEL_PLANNER_MODEL_ID="${SHISAD_MODEL_PLANNER_MODEL_ID:-gpt-5.2-2025-12-11}"
# Local M5/bootstrap route: allow planner model override without SHISA-default pin mismatch.
export SHISAD_MODEL_ENFORCE_SECURITY_ROUTE_PINNING="${SHISAD_MODEL_ENFORCE_SECURITY_ROUTE_PINNING:-false}"

required_credential=""
case "$SHISAD_MODEL_PLANNER_PROVIDER_PRESET" in
  openai_default)
    required_credential="OPENAI_API_KEY"
    ;;
  shisa_default)
    required_credential="SHISA_API_KEY"
    ;;
  openrouter_default)
    required_credential="OPENROUTER_API_KEY"
    ;;
  google_openai_default)
    required_credential="GEMINI_API_KEY"
    ;;
  vllm_local_default)
    required_credential=""
    ;;
  *)
    echo "warning: unknown planner preset '$SHISAD_MODEL_PLANNER_PROVIDER_PRESET'; skipping credential preflight" >&2
    ;;
esac

if [[ "$SHISAD_MODEL_PLANNER_REMOTE_ENABLED" == "true" ]] && [[ -n "$required_credential" ]] && [[ -z "${!required_credential:-}" ]]; then
  echo "$required_credential is required for planner preset '$SHISAD_MODEL_PLANNER_PROVIDER_PRESET'." >&2
  exit 1
fi

mkdir -p "$SHISAD_DATA_DIR"
mkdir -p "$(dirname "$SHISAD_POLICY_PATH")"
mkdir -p "$(dirname "$SHISAD_SOCKET_PATH")"

if [[ ! -f "$SHISAD_POLICY_PATH" ]]; then
  cat >"$SHISAD_POLICY_PATH" <<'EOF'
version: "1"
default_deny: false
default_require_confirmation: false

default_capabilities:
  - file.read
  - file.write
  - http.request
  - shell.exec

tools:
  report_anomaly: {}
  web_search:
    capabilities_required:
      - http.request
  web_fetch:
    capabilities_required:
      - http.request
  fs.list:
    capabilities_required:
      - file.read
  fs.read:
    capabilities_required:
      - file.read
  fs.write:
    capabilities_required:
      - file.write
    require_confirmation: true
  git.status:
    capabilities_required:
      - file.read
  git.diff:
    capabilities_required:
      - file.read
  git.log:
    capabilities_required:
      - file.read
EOF
fi

if [[ -e "$SHISAD_SOCKET_PATH" ]]; then
  rm -f "$SHISAD_SOCKET_PATH"
fi

echo "Starting shisad in debug mode with local M5/bootstrap defaults"
echo "  planner preset : $SHISAD_MODEL_PLANNER_PROVIDER_PRESET"
echo "  planner model  : $SHISAD_MODEL_PLANNER_MODEL_ID"
echo "  coding repo    : $SHISAD_CODING_REPO_ROOT"
echo "  agent pref     : $SHISAD_CODING_AGENT_DEFAULT_PREFERENCE"
echo "  fallbacks      : $SHISAD_CODING_AGENT_DEFAULT_FALLBACKS"
echo "  policy path    : $SHISAD_POLICY_PATH"
echo "  socket         : $SHISAD_SOCKET_PATH"
echo "  data dir       : $SHISAD_DATA_DIR"
echo "  agent auth     : inherited from current shell environment"

exec uv run shisad start --debug
