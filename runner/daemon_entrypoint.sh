#!/usr/bin/env bash
set -euo pipefail

# Internal runner entrypoint used by runner/harness.sh when launching the daemon
# in a persistent tmux session.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

debug=false
log_path=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --debug)
      debug=true
      ;;
    --foreground|--fg|-f)
      debug=false
      ;;
    --log-path)
      shift
      if [[ $# -eq 0 ]]; then
        printf '%s\n' "error: --log-path requires an absolute path" >&2
        exit 2
      fi
      log_path="$1"
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

if [[ -z "${log_path}" || "${log_path}" != /* ]]; then
  printf '%s\n' "error: --log-path requires an absolute path" >&2
  exit 2
fi
if [[ ! -d "$(dirname "${log_path}")" || -L "${log_path}" ]]; then
  printf '%s\n' "error: unsafe runner log path: ${log_path}" >&2
  exit 2
fi

umask 077
exec >>"${log_path}" 2>&1

if [[ "${debug}" == true ]]; then
  exec uv run shisad start --debug
fi
exec uv run shisad start --foreground
