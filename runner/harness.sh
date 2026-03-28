#!/usr/bin/env bash
set -euo pipefail

RUNNER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${RUNNER_DIR}/.." && pwd)"
DOTENV_PATH="${RUNNER_DIR}/.env"

_usage() {
  cat <<'EOF'
shisad runner harness

Usage:
  bash runner/harness.sh <command> [args...]

Commands:
  start [--fg] [--no-debug]   Start daemon (default: background + --debug)
  stop                        Stop daemon (RPC shutdown; falls back to PID kill)
  restart                     Stop then start
  status                      Show daemon status
  doctor [component]          Run doctor checks (default: all)
  logs [--follow] [--lines N] Tail daemon log
  events [args...]            Stream daemon events (shisad events subscribe ...)
  session new [--user U] [--workspace W] [--mode M]
  session say <id> <text...>
  session list
  shisad <args...>            Raw passthrough to "uv run shisad ..."
  env                         Print effective runner env + paths

Notes:
  - Private overrides: runner/.env (gitignored). Start from runner/.env.example.
  - Defaults match the v0.4 M5 runbook + ./run.sh where possible.
  - By default, the harness clears inherited SHISAD_* env (channels, socket paths, etc.)
    to keep runs deterministic and local-only. Set RUNNER_INHERIT_SHISAD_ENV=1 to opt out.
EOF
}

_warn() { printf '%s\n' "warning: $*" >&2; }
_die() { printf '%s\n' "error: $*" >&2; exit 1; }

_parse_env_file() {
  # Parse a KEY=VALUE env file safely (no shell sourcing).
  # Usage: _parse_env_file <path> <label>
  local path="$1"
  local label="${2:-${path}}"

  if [[ ! -f "${path}" ]]; then
    return 0
  fi

  while IFS= read -r line || [[ -n "${line}" ]]; do
    # Trim whitespace.
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line%"${line##*[![:space:]]}"}"
    [[ -z "${line}" ]] && continue
    [[ "${line}" == \#* ]] && continue

    # Optional leading "export ".
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

    # Validate key.
    if ! [[ "${key}" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
      _warn "ignoring invalid ${label} key: ${key}"
      continue
    fi

    # Strip surrounding quotes when present.
    if [[ "${val}" =~ ^\".*\"$ ]]; then
      val="${val:1:-1}"
    elif [[ "${val}" =~ ^\'.*\'$ ]]; then
      val="${val:1:-1}"
    fi

    export "${key}=${val}"
  done <"${path}"
}

_load_env_files() {
  # Load order (later files override earlier):
  #   1. SHISAD_ENV_FILE (canonical system/user env, e.g. ~/.config/shisad/runtime.env)
  #   2. runner/.env      (repo-local dev overrides)
  local sys_env="${SHISAD_ENV_FILE:-}"
  if [[ -n "${sys_env}" ]]; then
    _parse_env_file "${sys_env}" "SHISAD_ENV_FILE (${sys_env})"
  fi
  _parse_env_file "${DOTENV_PATH}" "runner/.env"
}

_clear_inherited_shisad_env() {
  # The runner harness is intentionally deterministic: it should not pick up a
  # previously-configured operator daemon environment (channels, sockets, etc.)
  # unless explicitly requested.
  unset SHISAD_ENV_FILE || true
  unset SHISAD_CHANNEL_IDENTITY_ALLOWLIST || true

  unset SHISAD_DATA_DIR SHISAD_SOCKET_PATH SHISAD_POLICY_PATH SHISAD_LOG_LEVEL || true
  unset SHISAD_CODING_REPO_ROOT SHISAD_ASSISTANT_FS_ROOTS || true
  unset SHISAD_CODING_AGENT_DEFAULT_PREFERENCE SHISAD_CODING_AGENT_DEFAULT_FALLBACKS || true
  unset SHISAD_CODING_AGENT_TIMEOUT_SECONDS || true

  unset SHISAD_MODEL_REMOTE_ENABLED SHISAD_MODEL_PLANNER_REMOTE_ENABLED || true
  unset SHISAD_MODEL_EMBEDDINGS_REMOTE_ENABLED SHISAD_MODEL_MONITOR_REMOTE_ENABLED || true
  unset SHISAD_MODEL_PLANNER_PROVIDER_PRESET SHISAD_MODEL_PLANNER_MODEL_ID || true
  unset SHISAD_MODEL_ENFORCE_SECURITY_ROUTE_PINNING || true

  # External channels (disabled by default).
  unset SHISAD_DISCORD_ENABLED SHISAD_DISCORD_BOT_TOKEN SHISAD_DISCORD_DEFAULT_CHANNEL_ID || true
  unset SHISAD_DISCORD_TRUSTED_USERS SHISAD_DISCORD_GUILD_WORKSPACE_MAP || true
  unset SHISAD_TELEGRAM_ENABLED SHISAD_TELEGRAM_BOT_TOKEN SHISAD_TELEGRAM_DEFAULT_CHAT_ID || true
  unset SHISAD_TELEGRAM_TRUSTED_USERS SHISAD_TELEGRAM_CHAT_WORKSPACE_MAP || true
  unset SHISAD_SLACK_ENABLED SHISAD_SLACK_BOT_TOKEN SHISAD_SLACK_APP_TOKEN || true
  unset SHISAD_SLACK_DEFAULT_CHANNEL_ID SHISAD_SLACK_TRUSTED_USERS || true
  unset SHISAD_SLACK_TEAM_WORKSPACE_MAP || true
  unset SHISAD_MATRIX_ENABLED SHISAD_MATRIX_HOMESERVER SHISAD_MATRIX_USER_ID || true
  unset SHISAD_MATRIX_ACCESS_TOKEN SHISAD_MATRIX_ROOM_ID SHISAD_MATRIX_E2EE || true
  unset SHISAD_MATRIX_TRUSTED_USERS SHISAD_MATRIX_ROOM_WORKSPACE_MAP || true
}

_export_defaults() {
  export SHISAD_DATA_DIR="${SHISAD_DATA_DIR:-$REPO_ROOT/.local/shisad-dev}"
  export SHISAD_SOCKET_PATH="${SHISAD_SOCKET_PATH:-/tmp/shisad-dev.sock}"
  export SHISAD_POLICY_PATH="${SHISAD_POLICY_PATH:-$REPO_ROOT/.local/policy.yaml}"
  export SHISAD_LOG_LEVEL="${SHISAD_LOG_LEVEL:-INFO}"
  export SHISAD_CODING_REPO_ROOT="${SHISAD_CODING_REPO_ROOT:-$REPO_ROOT}"
  export SHISAD_ASSISTANT_FS_ROOTS="${SHISAD_ASSISTANT_FS_ROOTS:-[\"$REPO_ROOT\"]}"
  export SHISAD_CODING_AGENT_DEFAULT_PREFERENCE="${SHISAD_CODING_AGENT_DEFAULT_PREFERENCE:-[\"codex\",\"claude\"]}"
  export SHISAD_CODING_AGENT_DEFAULT_FALLBACKS="${SHISAD_CODING_AGENT_DEFAULT_FALLBACKS:-[\"claude\"]}"
  export SHISAD_CODING_AGENT_TIMEOUT_SECONDS="${SHISAD_CODING_AGENT_TIMEOUT_SECONDS:-1800}"

  export SHISAD_MODEL_REMOTE_ENABLED="${SHISAD_MODEL_REMOTE_ENABLED:-false}"
  export SHISAD_MODEL_PLANNER_REMOTE_ENABLED="${SHISAD_MODEL_PLANNER_REMOTE_ENABLED:-true}"
  export SHISAD_MODEL_EMBEDDINGS_REMOTE_ENABLED="${SHISAD_MODEL_EMBEDDINGS_REMOTE_ENABLED:-false}"
  export SHISAD_MODEL_MONITOR_REMOTE_ENABLED="${SHISAD_MODEL_MONITOR_REMOTE_ENABLED:-false}"

  export SHISAD_MODEL_PLANNER_PROVIDER_PRESET="${SHISAD_MODEL_PLANNER_PROVIDER_PRESET:-shisa_default}"
  export SHISAD_MODEL_PLANNER_MODEL_ID="${SHISAD_MODEL_PLANNER_MODEL_ID:-shisa-ai/shisa-v2.1-unphi4-14b}"
  # Local M5/bootstrap route: allow planner model override without SHISA-default pin mismatch.
  export SHISAD_MODEL_ENFORCE_SECURITY_ROUTE_PINNING="${SHISAD_MODEL_ENFORCE_SECURITY_ROUTE_PINNING:-false}"

  # Keep runner starts local-only by default (no external channel connections).
  export SHISAD_MATRIX_ENABLED="${SHISAD_MATRIX_ENABLED:-false}"
  export SHISAD_DISCORD_ENABLED="${SHISAD_DISCORD_ENABLED:-false}"
  export SHISAD_TELEGRAM_ENABLED="${SHISAD_TELEGRAM_ENABLED:-false}"
  export SHISAD_SLACK_ENABLED="${SHISAD_SLACK_ENABLED:-false}"
}

_daemon_log_path() {
  printf '%s\n' "${SHISAD_DATA_DIR}/daemon.log"
}

_daemon_pid_path() {
  printf '%s\n' "${SHISAD_DATA_DIR}/daemon.pid"
}

_ensure_bootstrap_dirs() {
  mkdir -p "${SHISAD_DATA_DIR}"
  mkdir -p "$(dirname "${SHISAD_POLICY_PATH}")"
  mkdir -p "$(dirname "${SHISAD_SOCKET_PATH}")"
}

_ensure_policy_file() {
  if [[ -f "${SHISAD_POLICY_PATH}" ]]; then
    return 0
  fi

  local template="${RUNNER_DIR}/policy.default.yaml"
  if [[ ! -f "${template}" ]]; then
    _die "policy template not found: ${template}"
  fi

  cp "${template}" "${SHISAD_POLICY_PATH}"
  chmod 600 "${SHISAD_POLICY_PATH}" || true
}

_preflight_planner_credential() {
  local required=""
  case "${SHISAD_MODEL_PLANNER_PROVIDER_PRESET}" in
    openai_default)
      required="OPENAI_API_KEY"
      ;;
    shisa_default)
      required="SHISA_API_KEY"
      ;;
    openrouter_default)
      required="OPENROUTER_API_KEY"
      ;;
    google_openai_default)
      required="GEMINI_API_KEY"
      ;;
    vllm_local_default)
      required=""
      ;;
    *)
      _warn "unknown planner preset '${SHISAD_MODEL_PLANNER_PROVIDER_PRESET}'; skipping credential preflight"
      required=""
      ;;
  esac

  if [[ "${SHISAD_MODEL_PLANNER_REMOTE_ENABLED}" == "true" ]] && [[ -n "${required}" ]] && [[ -z "${!required:-}" ]]; then
    _die "${required} is required for planner preset '${SHISAD_MODEL_PLANNER_PROVIDER_PRESET}'. Set it in your shell or runner/.env."
  fi
}

_runner_env() {
  # Preserve SHISAD_ENV_FILE across the clear — it is the user's pointer to
  # their canonical credentials file and must survive env isolation.
  local saved_env_file="${SHISAD_ENV_FILE:-}"

  local inherit="${RUNNER_INHERIT_SHISAD_ENV:-}"
  if [[ "${inherit}" != "1" ]] && [[ "${inherit}" != "true" ]] && [[ "${inherit}" != "yes" ]]; then
    _clear_inherited_shisad_env
  fi

  # Restore the pointer so _load_env_files can use it.
  if [[ -n "${saved_env_file}" ]]; then
    export SHISAD_ENV_FILE="${saved_env_file}"
  fi

  _load_env_files
  _export_defaults
}

_shisad() {
  _runner_env
  uv run shisad "$@"
}

_tmux_socket_name() {
  printf '%s\n' "${RUNNER_TMUX_SOCKET_NAME:-shisad-dev}"
}

_tmux_session_name() {
  printf '%s\n' "${RUNNER_TMUX_SESSION_NAME:-shisad-dev}"
}

_tmux() {
  tmux -L "$(_tmux_socket_name)" "$@"
}

_cmd_env() {
  _runner_env
  cat <<EOF
REPO_ROOT=${REPO_ROOT}
DOTENV_PATH=${DOTENV_PATH}
RUNNER_TMUX_SOCKET_NAME=$(_tmux_socket_name)
RUNNER_TMUX_SESSION_NAME=$(_tmux_session_name)

SHISAD_DATA_DIR=${SHISAD_DATA_DIR}
SHISAD_SOCKET_PATH=${SHISAD_SOCKET_PATH}
SHISAD_POLICY_PATH=${SHISAD_POLICY_PATH}
SHISAD_CODING_REPO_ROOT=${SHISAD_CODING_REPO_ROOT}
SHISAD_ASSISTANT_FS_ROOTS=${SHISAD_ASSISTANT_FS_ROOTS}

DAEMON_LOG=$(_daemon_log_path)
DAEMON_PID=$(_daemon_pid_path)
EOF
}

_cmd_start() {
  local fg=false
  local debug=true

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --fg|--foreground|-f)
        fg=true
        ;;
      --no-debug)
        debug=false
        ;;
      --debug)
        debug=true
        ;;
      -h|--help)
        _usage
        return 0
        ;;
      *)
        _die "unknown start arg: $1"
        ;;
    esac
    shift
  done

  _runner_env
  _ensure_bootstrap_dirs
  _ensure_policy_file
  _preflight_planner_credential

  local log_path pid_path
  log_path="$(_daemon_log_path)"
  pid_path="$(_daemon_pid_path)"

  if uv run shisad status >/dev/null 2>&1; then
    printf '%s\n' "Daemon already running (socket: ${SHISAD_SOCKET_PATH})"
    return 0
  fi

  if [[ -e "${SHISAD_SOCKET_PATH}" ]]; then
    rm -f "${SHISAD_SOCKET_PATH}" || true
  fi

  if [[ "${fg}" == true ]]; then
    printf '%s\n' "Starting shisad in foreground (debug=${debug})"
    printf '%s\n' "  socket   : ${SHISAD_SOCKET_PATH}"
    printf '%s\n' "  data dir : ${SHISAD_DATA_DIR}"
    printf '%s\n' "  policy   : ${SHISAD_POLICY_PATH}"
    if [[ "${debug}" == true ]]; then
      exec uv run shisad start --debug
    fi
    exec uv run shisad start --foreground
  fi

  printf '%s\n' "Starting shisad in background (debug=${debug})"
  printf '%s\n' "  log      : ${log_path}"
  printf '%s\n' "  socket   : ${SHISAD_SOCKET_PATH}"
  printf '%s\n' "  data dir : ${SHISAD_DATA_DIR}"

  rm -f "${pid_path}" || true
  rm -f "${log_path}" || true

  if ! command -v tmux >/dev/null 2>&1; then
    _die "tmux is required for background start. Install tmux or run: bash runner/harness.sh start --fg"
  fi

  local session
  session="$(_tmux_session_name)"

  if _tmux has-session -t "${session}" >/dev/null 2>&1; then
    printf '%s\n' "tmux session already exists: ${session}"
    printf '%s\n' "Use: tmux -L $(_tmux_socket_name) attach -t ${session}"
    return 0
  fi

  local daemon_args=""
  if [[ "${debug}" == true ]]; then
    daemon_args="--debug"
  else
    daemon_args="--foreground"
  fi

  # Run in tmux so the daemon survives across non-interactive shells.
  _tmux new-session -d -s "${session}" -c "${REPO_ROOT}" "bash runner/daemon_entrypoint.sh ${daemon_args}"

  # Wait for socket + status to succeed.
  local i
  for i in {1..150}; do
    if uv run shisad status >/dev/null 2>&1; then
      printf '%s\n' "Daemon is up."
      return 0
    fi
    sleep 0.2
  done

  _warn "daemon did not become ready in time; last log lines:"
  tail -n 80 "${log_path}" || true
  return 1
}

_cmd_stop() {
  _runner_env

  local pid_path
  pid_path="$(_daemon_pid_path)"

  uv run shisad stop >/dev/null 2>&1 || true

  if command -v tmux >/dev/null 2>&1; then
    local session
    session="$(_tmux_session_name)"
    if _tmux has-session -t "${session}" >/dev/null 2>&1; then
      _tmux kill-session -t "${session}" >/dev/null 2>&1 || true
    fi
  fi

  rm -f "${pid_path}" || true

  if [[ -e "${SHISAD_SOCKET_PATH}" ]]; then
    rm -f "${SHISAD_SOCKET_PATH}" || true
  fi

  printf '%s\n' "Daemon stop requested."
}

_cmd_restart() {
  _cmd_stop
  _cmd_start
}

_cmd_status() {
  _shisad status
}

_cmd_doctor() {
  local component="${1:-all}"
  _shisad doctor check --component "${component}"
}

_cmd_logs() {
  _runner_env

  local follow=false
  local lines=200

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --follow|-f)
        follow=true
        ;;
      --lines)
        shift
        [[ $# -gt 0 ]] || _die "--lines requires a value"
        lines="$1"
        ;;
      -h|--help)
        printf '%s\n' "Usage: bash runner/harness.sh logs [--follow] [--lines N]"
        return 0
        ;;
      *)
        _die "unknown logs arg: $1"
        ;;
    esac
    shift
  done

  local log_path
  log_path="$(_daemon_log_path)"
  if [[ ! -f "${log_path}" ]]; then
    _die "log file not found: ${log_path} (start the daemon first)"
  fi

  if [[ "${follow}" == true ]]; then
    tail -n "${lines}" -f "${log_path}"
    return 0
  fi
  tail -n "${lines}" "${log_path}"
}

_cmd_events() {
  _runner_env
  uv run shisad events subscribe "$@"
}

_cmd_session() {
  local sub="${1:-}"
  shift || true

  case "${sub}" in
    new)
      _runner_env
      local out session_id
      out="$(uv run shisad session create "$@" 2>&1)"
      session_id=""
      while IFS= read -r line; do
        line="${line//$'\r'/}"
        if [[ "${line}" == *"Session created:"* ]]; then
          line="${line#*Session created: }"
          session_id="${line%% *}"
          break
        fi
      done <<<"${out}"
      if [[ -z "${session_id}" ]]; then
        printf '%s\n' "${out}" >&2
        _die "failed to parse session id"
      fi
      printf '%s\n' "${session_id}"
      ;;
    say)
      _runner_env
      [[ $# -ge 2 ]] || _die "usage: session say <session_id> <text...>"
      local session_id="$1"
      shift
      local content="$*"
      uv run shisad session message "${session_id}" "${content}"
      ;;
    list)
      _shisad session list
      ;;
    *)
      _die "unknown session subcommand: ${sub} (expected: new|say|list)"
      ;;
  esac
}

main() {
  local cmd="${1:-}"
  shift || true

  case "${cmd}" in
    ""|-h|--help|help)
      _usage
      ;;
    env)
      _cmd_env
      ;;
    start)
      _cmd_start "$@"
      ;;
    stop)
      _cmd_stop
      ;;
    restart)
      _cmd_restart
      ;;
    status)
      _cmd_status
      ;;
    doctor)
      _cmd_doctor "$@"
      ;;
    logs)
      _cmd_logs "$@"
      ;;
    events)
      _cmd_events "$@"
      ;;
    session)
      _cmd_session "$@"
      ;;
    shisad)
      _shisad "$@"
      ;;
    *)
      _die "unknown command: ${cmd}"
      ;;
  esac
}

main "$@"
