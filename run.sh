#!/usr/bin/env bash
set -euo pipefail

# Thin compatibility shim — delegates to runner/harness.sh.
#
# For full control (background start, logs, sessions, doctor, etc.) use
# runner/harness.sh directly.  This script exists so that `./run.sh`
# continues to work as a quick foreground launcher.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec bash "${REPO_ROOT}/runner/harness.sh" start --fg "$@"
