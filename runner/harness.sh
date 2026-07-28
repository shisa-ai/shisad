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
  shisad <args...>            Raw passthrough to "uv --no-config run --frozen --python 3.12 shisad ..."
  env                         Print effective runner env + paths

Notes:
  - Private overrides: runner/.env (gitignored). Start from runner/.env.example.
  - Defaults are version-agnostic and match runner/RUNBOOK.md.
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

_default_user_socket_path() {
  if [[ -n "${XDG_RUNTIME_DIR:-}" ]] && [[ "${XDG_RUNTIME_DIR}" = /* ]]; then
    printf '%s\n' "${XDG_RUNTIME_DIR}/shisad/control.sock"
    return 0
  fi

  local uid
  uid="$(id -u)"
  printf '%s\n' "/tmp/shisad-${uid}/control.sock"
}

_stat_uid() {
  stat -c '%u' "$1" 2>/dev/null || stat -f '%u' "$1"
}

_socket_dir_requires_private() {
  local dir="$1"
  local uid
  uid="$(id -u)"

  if [[ "${dir}" == "/tmp/shisad-${uid}" ]]; then
    return 0
  fi

  if [[ -n "${XDG_RUNTIME_DIR:-}" ]] && [[ "${XDG_RUNTIME_DIR}" = /* ]] \
    && [[ "${dir}" == "${XDG_RUNTIME_DIR}/shisad" ]]; then
    return 0
  fi

  return 1
}

_ensure_private_dir() {
  local dir="$1"
  local create="${2:-false}"

  if [[ "${create}" == true ]]; then
    if [[ -L "${dir}" ]]; then
      _die "unsafe socket directory: ${dir} is a symlink"
    fi
    mkdir -p -m 700 "${dir}"
  elif [[ ! -e "${dir}" ]]; then
    return 0
  fi

  if [[ -L "${dir}" ]]; then
    _die "unsafe socket directory: ${dir} is a symlink"
  fi
  if [[ ! -d "${dir}" ]]; then
    _die "unsafe socket directory: ${dir} is not a directory"
  fi

  local owner uid
  owner="$(_stat_uid "${dir}")" || _die "unable to stat socket directory owner: ${dir}"
  uid="$(id -u)"
  if [[ "${owner}" != "${uid}" ]]; then
    _die "unsafe socket directory: ${dir} is owned by uid ${owner}, expected ${uid}"
  fi

  local mode
  mode="$(stat -c '%a' "${dir}" 2>/dev/null || stat -f '%Lp' "${dir}")"
  if [[ "${mode}" != "700" ]]; then
    if [[ "${create}" != true ]]; then
      _die "unsafe socket directory: ${dir} has mode ${mode}, expected 700"
    fi
    chmod 700 "${dir}" || _die "unable to restrict socket directory permissions: ${dir}"
  fi
}

_preflight_socket_parent() {
  local create="${1:-false}"
  local socket_dir
  socket_dir="$(dirname "$(_runner_socket_path)")"

  if ! _socket_dir_requires_private "${socket_dir}"; then
    if [[ "${create}" == true ]]; then
      mkdir -p "${socket_dir}"
    fi
    return 0
  fi

  if [[ -n "${XDG_RUNTIME_DIR:-}" ]] && [[ "${XDG_RUNTIME_DIR}" = /* ]] \
    && [[ "${socket_dir}" == "${XDG_RUNTIME_DIR}/shisad" ]]; then
    _ensure_private_dir "${XDG_RUNTIME_DIR}" "${create}"
  fi

  _ensure_private_dir "${socket_dir}" "${create}"
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

_runner_config_state() {
  (
    cd "${REPO_ROOT}"
    uv --no-config run --frozen --python 3.12 python - <<'PY'
import sys

from shisad.core.config_file import ConfigFileError, load_effective_config

try:
    loaded = load_effective_config()
except ConfigFileError as exc:
    print(str(exc), file=sys.stderr)
    raise SystemExit(2) from None
print("selected" if loaded.daemon.config_path is not None else "absent")
PY
  )
}

_load_config_runner_context() {
  RUNNER_EFFECTIVE_DATA_DIR=""
  RUNNER_EFFECTIVE_SOCKET_PATH=""
  RUNNER_EFFECTIVE_POLICY_PATH=""
  RUNNER_EFFECTIVE_CODING_REPO_ROOT=""
  RUNNER_EFFECTIVE_ASSISTANT_FS_ROOTS=""
  while IFS= read -r -d '' key && IFS= read -r -d '' value; do
    case "${key}" in
      data_dir) RUNNER_EFFECTIVE_DATA_DIR="${value}" ;;
      socket_path) RUNNER_EFFECTIVE_SOCKET_PATH="${value}" ;;
      policy_path) RUNNER_EFFECTIVE_POLICY_PATH="${value}" ;;
      coding_repo_root) RUNNER_EFFECTIVE_CODING_REPO_ROOT="${value}" ;;
      assistant_fs_roots) RUNNER_EFFECTIVE_ASSISTANT_FS_ROOTS="${value}" ;;
      *) _die "unexpected config context field: ${key}" ;;
    esac
  done < <(
    cd "${REPO_ROOT}"
    uv --no-config run --frozen --python 3.12 python - <<'PY'
import json
import sys

from shisad.core.config_file import load_effective_config

daemon = load_effective_config().daemon
pairs = (
    ("data_dir", str(daemon.data_dir)),
    ("socket_path", str(daemon.socket_path)),
    ("policy_path", str(daemon.policy_path)),
    ("coding_repo_root", str(daemon.coding_repo_root)),
    (
        "assistant_fs_roots",
        json.dumps([str(path) for path in daemon.assistant_fs_roots]),
    ),
)
for key, value in pairs:
    sys.stdout.buffer.write(key.encode("utf-8") + b"\0")
    sys.stdout.buffer.write(value.encode("utf-8") + b"\0")
PY
  )
  [[ -n "${RUNNER_EFFECTIVE_DATA_DIR}" ]] || _die "config data_dir was not resolved"
  [[ -n "${RUNNER_EFFECTIVE_SOCKET_PATH}" ]] || _die "config socket_path was not resolved"
  [[ -n "${RUNNER_EFFECTIVE_POLICY_PATH}" ]] || _die "config policy_path was not resolved"
  export RUNNER_EFFECTIVE_DATA_DIR RUNNER_EFFECTIVE_SOCKET_PATH
}

_runner_data_dir() {
  printf '%s\n' "${RUNNER_EFFECTIVE_DATA_DIR:-${SHISAD_DATA_DIR:-}}"
}

_runner_socket_path() {
  printf '%s\n' "${RUNNER_EFFECTIVE_SOCKET_PATH:-${SHISAD_SOCKET_PATH:-}}"
}

_runner_policy_path() {
  printf '%s\n' "${RUNNER_EFFECTIVE_POLICY_PATH:-${SHISAD_POLICY_PATH:-}}"
}

_export_defaults() {
  export SHISAD_DATA_DIR="${SHISAD_DATA_DIR:-$REPO_ROOT/.local/shisad-dev}"
  export SHISAD_SOCKET_PATH="${SHISAD_SOCKET_PATH:-$(_default_user_socket_path)}"
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
  # Dev route: allow planner model override without SHISA-default pin mismatch.
  export SHISAD_MODEL_ENFORCE_SECURITY_ROUTE_PINNING="${SHISAD_MODEL_ENFORCE_SECURITY_ROUTE_PINNING:-false}"

  # Keep runner starts local-only by default (no external channel connections).
  export SHISAD_MATRIX_ENABLED="${SHISAD_MATRIX_ENABLED:-false}"
  export SHISAD_DISCORD_ENABLED="${SHISAD_DISCORD_ENABLED:-false}"
  export SHISAD_TELEGRAM_ENABLED="${SHISAD_TELEGRAM_ENABLED:-false}"
  export SHISAD_SLACK_ENABLED="${SHISAD_SLACK_ENABLED:-false}"
}

_daemon_log_path() {
  printf '%s\n' "$(_runner_data_dir)/daemon.log"
}

_daemon_pid_path() {
  printf '%s\n' "$(_runner_data_dir)/daemon.pid"
}

_ensure_bootstrap_dirs() {
  mkdir -p "$(_runner_data_dir)"
  mkdir -p "$(dirname "$(_runner_policy_path)")"
  _preflight_socket_parent true
}

_ensure_policy_file() {
  local policy_path
  policy_path="$(_runner_policy_path)"
  if [[ -f "${policy_path}" ]]; then
    return 0
  fi

  local template="${RUNNER_DIR}/policy.default.yaml"
  if [[ ! -f "${template}" ]]; then
    _die "policy template not found: ${template}"
  fi

  cp "${template}" "${policy_path}"
  chmod 600 "${policy_path}" || true
}

_preflight_planner_credential_from_config() {
  (
    cd "${REPO_ROOT}"
    uv --no-config run --frozen --python 3.12 python - <<'PY'
import sys

from shisad.core.config_file import ConfigFileError, load_effective_config
from shisad.core.providers.capabilities import AuthMode
from shisad.core.providers.routing import ModelComponent, ModelRouter

try:
    route = ModelRouter(load_effective_config().model).route_for(ModelComponent.PLANNER)
except (ConfigFileError, ValueError) as exc:
    print(str(exc), file=sys.stderr)
    raise SystemExit(2) from None
if not route.remote_enabled or route.auth_mode == AuthMode.NONE or route.api_key:
    raise SystemExit(0)
print(
    f"planner route '{route.provider_preset.value}' requires a configured credential",
    file=sys.stderr,
)
raise SystemExit(1)
PY
  )
}

_preflight_planner_credential() {
  if [[ "${RUNNER_CONFIG_SELECTED:-false}" == true ]]; then
    _preflight_planner_credential_from_config
    return
  fi
  # Explicit route and global model keys are first-class runtime inputs. Keep
  # this check ahead of preset-key handling so the harness accepts the same
  # supported configurations as ModelRouter._resolve_route_api_key().
  if [[ -n "${SHISAD_MODEL_PLANNER_API_KEY:-}" ]] || [[ -n "${SHISAD_MODEL_API_KEY:-}" ]]; then
    return 0
  fi

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
    anthropic_default)
      required="ANTHROPIC_API_KEY"
      ;;
    vllm_local_default)
      required=""
      ;;
    *)
      _warn "unknown planner preset '${SHISAD_MODEL_PLANNER_PROVIDER_PRESET}'; skipping credential preflight"
      required=""
      ;;
  esac

  if [[ "${SHISAD_MODEL_PLANNER_REMOTE_ENABLED}" != "true" ]] || [[ -z "${required}" ]]; then
    return 0
  fi

  # Key present for the configured preset — nothing to do.
  if [[ -n "${!required:-}" ]]; then
    return 0
  fi

  # Key missing. If the user explicitly chose a non-default preset, fail immediately.
  if [[ "${SHISAD_MODEL_PLANNER_PROVIDER_PRESET}" != "shisa_default" ]]; then
    _die "${required} is required for planner preset '${SHISAD_MODEL_PLANNER_PROVIDER_PRESET}'. Set it in your shell or runner/.env."
  fi

  # Default preset (shisa_default) and SHISA_API_KEY is missing — try to
  # auto-detect an alternative API key.  Order mirrors the Python-side
  # ModelRouter._auto_detect_preset_from_api_key() priority.
  local fallback_key="" fallback_preset="" fallback_model=""
  if [[ -n "${OPENAI_API_KEY:-}" ]]; then
    fallback_key="OPENAI_API_KEY"
    fallback_preset="openai_default"
    fallback_model="gpt-5.4-2026-03-05"
  elif [[ -n "${GEMINI_API_KEY:-}" ]]; then
    fallback_key="GEMINI_API_KEY"
    fallback_preset="google_openai_default"
    fallback_model="gemini-3.1-pro-preview"
  elif [[ -n "${OPENROUTER_API_KEY:-}" ]]; then
    fallback_key="OPENROUTER_API_KEY"
    fallback_preset="openrouter_default"
    fallback_model=""  # no default override; uses Python-side defaults
  elif [[ -n "${ANTHROPIC_API_KEY:-}" ]]; then
    fallback_key="ANTHROPIC_API_KEY"
    fallback_preset="anthropic_default"
    fallback_model="claude-sonnet-4-6"
  fi

  if [[ -z "${fallback_key}" ]]; then
    _die "No API key found. Set SHISA_API_KEY, OPENAI_API_KEY, GEMINI_API_KEY, OPENROUTER_API_KEY, or ANTHROPIC_API_KEY in your shell or runner/.env."
  fi

  _warn "SHISA_API_KEY not set; falling back to ${fallback_key} (preset: ${fallback_preset})"
  export SHISAD_MODEL_PLANNER_PROVIDER_PRESET="${fallback_preset}"
  if [[ -n "${fallback_model}" ]]; then
    export SHISAD_MODEL_PLANNER_MODEL_ID="${fallback_model}"
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
  local config_state
  if ! config_state="$(_runner_config_state)"; then
    _die "unable to load effective runner configuration"
  fi
  if [[ "${config_state}" == "selected" ]]; then
    RUNNER_CONFIG_SELECTED=true
    _load_config_runner_context
  else
    RUNNER_CONFIG_SELECTED=false
    _export_defaults
  fi
  export RUNNER_CONFIG_SELECTED
}

_shisad() {
  _runner_env
  _preflight_socket_parent false
  uv --no-config run --frozen --python 3.12 shisad "$@"
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
  local data_dir socket_path policy_path coding_repo_root assistant_fs_roots
  data_dir="$(_runner_data_dir)"
  socket_path="$(_runner_socket_path)"
  policy_path="$(_runner_policy_path)"
  coding_repo_root="${RUNNER_EFFECTIVE_CODING_REPO_ROOT:-${SHISAD_CODING_REPO_ROOT:-}}"
  assistant_fs_roots="${RUNNER_EFFECTIVE_ASSISTANT_FS_ROOTS:-${SHISAD_ASSISTANT_FS_ROOTS:-}}"
  cat <<EOF
REPO_ROOT=${REPO_ROOT}
DOTENV_PATH=${DOTENV_PATH}
RUNNER_TMUX_SOCKET_NAME=$(_tmux_socket_name)
RUNNER_TMUX_SESSION_NAME=$(_tmux_session_name)

SHISAD_DATA_DIR=${data_dir}
SHISAD_SOCKET_PATH=${socket_path}
SHISAD_POLICY_PATH=${policy_path}
SHISAD_CODING_REPO_ROOT=${coding_repo_root}
SHISAD_ASSISTANT_FS_ROOTS=${assistant_fs_roots}

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
  _preflight_socket_parent false
  _ensure_bootstrap_dirs
  _ensure_policy_file
  _preflight_planner_credential

  local log_path pid_path socket_path data_dir policy_path
  log_path="$(_daemon_log_path)"
  pid_path="$(_daemon_pid_path)"
  socket_path="$(_runner_socket_path)"
  data_dir="$(_runner_data_dir)"
  policy_path="$(_runner_policy_path)"

  if uv --no-config run --frozen --python 3.12 shisad status >/dev/null 2>&1; then
    printf '%s\n' "Daemon already running (socket: ${socket_path})"
    return 0
  fi

  if [[ -e "${socket_path}" ]]; then
    rm -f "${socket_path}" || true
  fi

  if [[ "${fg}" == true ]]; then
    printf '%s\n' "Starting shisad in foreground (debug=${debug})"
    printf '%s\n' "  socket   : ${socket_path}"
    printf '%s\n' "  data dir : ${data_dir}"
    printf '%s\n' "  policy   : ${policy_path}"
    if [[ "${debug}" == true ]]; then
      exec uv --no-config run --frozen --python 3.12 shisad start --debug
    fi
    exec uv --no-config run --frozen --python 3.12 shisad start --foreground
  fi

  printf '%s\n' "Starting shisad in background (debug=${debug})"
  printf '%s\n' "  log      : ${log_path}"
  printf '%s\n' "  socket   : ${socket_path}"
  printf '%s\n' "  data dir : ${data_dir}"

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
  if [[ "${RUNNER_CONFIG_SELECTED}" == true ]]; then
    local selected_command
    printf -v selected_command \
      'mkdir -p %q; exec uv --no-config run --frozen --python 3.12 shisad start %q >>%q 2>&1' \
      "${data_dir}" "${daemon_args}" "${log_path}"
    _tmux new-session -d -s "${session}" -c "${REPO_ROOT}" \
      "bash -c $(printf '%q' "${selected_command}")"
  else
    _tmux new-session -d -s "${session}" -c "${REPO_ROOT}" "bash runner/daemon_entrypoint.sh ${daemon_args}"
  fi

  # Wait for socket + status to succeed.
  local i
  for i in {1..150}; do
    if uv --no-config run --frozen --python 3.12 shisad status >/dev/null 2>&1; then
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
  _preflight_socket_parent false

  local pid_path socket_path
  pid_path="$(_daemon_pid_path)"
  socket_path="$(_runner_socket_path)"

  uv --no-config run --frozen --python 3.12 shisad stop >/dev/null 2>&1 || true

  if command -v tmux >/dev/null 2>&1; then
    local session
    session="$(_tmux_session_name)"
    if _tmux has-session -t "${session}" >/dev/null 2>&1; then
      _tmux kill-session -t "${session}" >/dev/null 2>&1 || true
    fi
  fi

  rm -f "${pid_path}" || true

  if [[ -e "${socket_path}" ]]; then
    rm -f "${socket_path}" || true
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
  _preflight_socket_parent false
  uv --no-config run --frozen --python 3.12 shisad events subscribe "$@"
}

_cmd_session() {
  local sub="${1:-}"
  shift || true

  case "${sub}" in
    new)
      _runner_env
      _preflight_socket_parent false
      local out session_id
      out="$(uv --no-config run --frozen --python 3.12 shisad session create "$@" 2>&1)"
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
      _preflight_socket_parent false
      [[ $# -ge 2 ]] || _die "usage: session say <session_id> <text...>"
      local session_id="$1"
      shift
      local content="$*"
      uv --no-config run --frozen --python 3.12 shisad session message "${session_id}" "${content}"
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
