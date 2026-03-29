#!/usr/bin/env bash
set -euo pipefail

# v0.5 end-to-end demo script:
# boot -> reminders -> web.fetch -> evidence refs -> credential isolation (component path)
#
# This script intentionally runs the daemon with a local (non-remote) planner so it works
# without API keys and so the demo behavior is deterministic. Explicit-intent commands
# ("fetch ...", "remind me ...", "read evidence ...") trigger tool calls directly.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

_die() {
  printf '%s\n' "error: $*" >&2
  exit 1
}

_require_cmd() {
  command -v "$1" >/dev/null 2>&1 || _die "$1 is required"
}

_require_cmd bash
_require_cmd uv

DEMO_ROOT="$(mktemp -d)"

export RUNNER_INHERIT_SHISAD_ENV=1
export SHISAD_DATA_DIR="${DEMO_ROOT}/data"
export SHISAD_SOCKET_PATH="${DEMO_ROOT}/shisad.sock"
export SHISAD_POLICY_PATH="${DEMO_ROOT}/policy.yaml"

export SHISAD_MODEL_REMOTE_ENABLED=false
export SHISAD_MODEL_PLANNER_REMOTE_ENABLED=false
export SHISAD_MODEL_EMBEDDINGS_REMOTE_ENABLED=false
export SHISAD_MODEL_MONITOR_REMOTE_ENABLED=false

export RUNNER_TMUX_SOCKET_NAME="shisad-demo-$(date +%s)-$$"
export RUNNER_TMUX_SESSION_NAME="${RUNNER_TMUX_SOCKET_NAME}"

DAEMON_FG_PID=""

cleanup() {
  set +e
  bash runner/harness.sh stop >/dev/null 2>&1 || true
  if [[ -n "${DAEMON_FG_PID}" ]]; then
    kill "${DAEMON_FG_PID}" >/dev/null 2>&1 || true
  fi
  rm -rf "${DEMO_ROOT}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "== Boot daemon =="
if command -v tmux >/dev/null 2>&1; then
  bash runner/harness.sh start --no-debug
else
  echo "tmux not found; starting daemon in background process mode."
  bash runner/harness.sh start --fg --no-debug >"${DEMO_ROOT}/daemon.log" 2>&1 &
  DAEMON_FG_PID="$!"

  for _ in {1..80}; do
    if bash runner/harness.sh shisad status >/dev/null 2>&1; then
      break
    fi
    sleep 0.25
  done

  if ! bash runner/harness.sh shisad status >/dev/null 2>&1; then
    echo "Last daemon log lines:" >&2
    tail -n 80 "${DEMO_ROOT}/daemon.log" >&2 || true
    _die "daemon did not become ready"
  fi
fi

SESSION_ID="$(bash runner/harness.sh session new --user demo --workspace demo)"
echo "session_id=${SESSION_ID}"

echo
echo "== Reminders (schedule then auto-deliver) =="
bash runner/harness.sh session say "${SESSION_ID}" "remind me to demo ping in 2 seconds"
echo
echo "tasks (before sleep):"
bash runner/harness.sh shisad task list
sleep 3
echo
echo "tasks (after sleep):"
bash runner/harness.sh shisad task list

echo
echo "== Web fetch (evidence-wrapped) =="
FETCH_RESPONSE="$(bash runner/harness.sh session say "${SESSION_ID}" "fetch https://example.com")"
printf '%s\n' "${FETCH_RESPONSE}"

EVIDENCE_REF_ID="$(
  printf '%s' "${FETCH_RESPONSE}" \
    | uv run python -c 'import re,sys; text=sys.stdin.read(); m=re.search(r"ref=(ev-[0-9a-f]+)", text); print(m.group(1) if m else "")'
)"
if [[ -z "${EVIDENCE_REF_ID}" ]]; then
  _die "failed to parse evidence ref id from fetch response"
fi
echo "evidence_ref_id=${EVIDENCE_REF_ID}"

echo
echo "== Read evidence (ephemeral; content returned in tool_outputs) =="
uv run python - "${SESSION_ID}" "${EVIDENCE_REF_ID}" <<'PY'
import asyncio
import os
import sys
from pathlib import Path

from shisad.core.api.transport import ControlClient

SESSION_ID = sys.argv[1]
REF_ID = sys.argv[2]


async def main() -> None:
    socket_path = Path(os.environ["SHISAD_SOCKET_PATH"])
    client = ControlClient(socket_path=socket_path)
    await client.connect()
    result = await client.call(
        "session.message",
        {"session_id": SESSION_ID, "content": f"read evidence {REF_ID}"},
    )
    await client.close()

    response = str(result.get("response", "")).rstrip()
    if response:
        print(response)

    content = ""
    for record in result.get("tool_outputs", []):
        if str(record.get("tool_name", "")) != "evidence.read":
            continue
        payload = record.get("payload")
        if isinstance(payload, dict):
            content = str(payload.get("content", ""))
        break

    if not content.strip():
        print("(no evidence content returned)")
        return

    lines = content.splitlines()
    head = lines[:40]
    print()
    print("evidence.read content preview (first 40 lines):")
    print("\n".join(head))


asyncio.run(main())
PY

echo
echo "== Credential isolation demo (component path) =="
uv run python scripts/demo_credential_isolation.py

echo
echo "Demo completed."
