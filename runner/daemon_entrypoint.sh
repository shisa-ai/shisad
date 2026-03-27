#!/usr/bin/env bash
set -euo pipefail

# Internal runner entrypoint used by runner/harness.sh when launching the daemon
# in a persistent tmux session.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

debug=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    --debug)
      debug=true
      ;;
    --foreground|--fg|-f)
      debug=false
      ;;
    *)
      printf '%s\n' "error: unknown daemon_entrypoint arg: $1" >&2
      exit 2
      ;;
  esac
  shift
done

if [[ -z "${SHISAD_DATA_DIR:-}" ]]; then
  printf '%s\n' "error: SHISAD_DATA_DIR is required" >&2
  exit 2
fi

mkdir -p "${SHISAD_DATA_DIR}"

log_path="${SHISAD_DATA_DIR}/daemon.log"
exec >>"${log_path}" 2>&1

# Best-effort cleanup of stale sockets; the harness also does this.
if [[ -n "${SHISAD_SOCKET_PATH:-}" ]] && [[ -e "${SHISAD_SOCKET_PATH}" ]]; then
  rm -f "${SHISAD_SOCKET_PATH}" || true
fi

if [[ "${debug}" == true ]]; then
  exec uv run shisad start --debug
fi
exec uv run shisad start --foreground

