# Runner Harness (Live Daemon + CLI)

This file is the "how to operate shisad locally" playbook intended for agentic coders. The goal is that any coding agent can bootstrap a live daemon, inspect logs/events, and send messages or run admin `dev.*` workflows without guessing about env/config.

## What Lives Here

- `runner/harness.sh`: the one entrypoint. It sets a safe default M5-capable env, starts/stops the daemon, tails logs, and wraps `uv run shisad ...` so the CLI always targets the same socket.
- `runner/.env.example`: template for private overrides (copy to `runner/.env`, which is gitignored).
- `.local/`: runtime artifacts (gitignored):
  - `.local/shisad-m5/daemon.log`, `.local/shisad-m5/daemon.pid`
  - `.local/policy.yaml` (auto-created if missing)

## Preconditions

- You are in the `shisad` repo root.
- Python deps are installed (example: `uv sync --dev`).
- If you want *live* remote planner calls, you have the right API key set for your preset (examples below).
- If you want to run `shisad dev implement/review/remediate`, at least one coding-agent CLI is installed and already authenticated in the *daemon's* environment (the daemon inherits your shell env when started).

## Private Env Overrides (`runner/.env`)

Copy the template and fill in local-only values:

```bash
cp runner/.env.example runner/.env
```

Supported formats:

- `KEY=value`
- `KEY="value"`
- `KEY='value'`

The harness treats `runner/.env` as data (no `source`); it only exports `KEY=VALUE` lines.

## Quickstart

Runbook (M5 operator path): [`runner/RUNBOOK.md`](RUNBOOK.md).

Start a daemon and follow logs:

```bash
bash runner/harness.sh start
bash runner/harness.sh logs --follow
```

Verify connectivity and basic runtime diagnostics:

```bash
bash runner/harness.sh status
bash runner/harness.sh doctor all
```

Talk to the daemon via session RPC:

```bash
session_id="$(bash runner/harness.sh session new --user ops --workspace local)"
bash runner/harness.sh session say "$session_id" "Say hello in one short sentence."
```

Stream structured events (useful when debugging tools/dev loop):

```bash
bash runner/harness.sh events
```

Run admin dev-loop commands (M5 path):

```bash
bash runner/harness.sh shisad dev implement \
  "Implement the scoped M5 task and keep it proposal-first." \
  --agent codex \
  --file-ref early v0.4 prototype direction
```

## Common Knobs

The harness sets defaults if you do not provide them:

- `SHISAD_DATA_DIR` (default: `.local/shisad-m5`)
- `SHISAD_SOCKET_PATH` (default: `/tmp/shisad-m5.sock`)
- `SHISAD_POLICY_PATH` (default: `.local/policy.yaml`)
- `SHISAD_CODING_REPO_ROOT` (default: repo root)

Planner preset credentials:

- `openai_default` needs `OPENAI_API_KEY`
- `shisa_default` needs `SHISA_API_KEY`
- `openrouter_default` needs `OPENROUTER_API_KEY`
- `google_openai_default` needs `GEMINI_API_KEY`

If you want to avoid remote planner calls (local/offline runs), set:

```bash
SHISAD_MODEL_PLANNER_REMOTE_ENABLED=false
```

## Command Reference

```bash
# Daemon lifecycle
bash runner/harness.sh start            # start in background; logs to .local/shisad-m5/daemon.log
bash runner/harness.sh start --fg       # run in foreground (like ./run.sh)
bash runner/harness.sh stop
bash runner/harness.sh restart

# Health
bash runner/harness.sh status
bash runner/harness.sh doctor all

# Logs and events
bash runner/harness.sh logs
bash runner/harness.sh logs --follow
bash runner/harness.sh events           # shisad events subscribe (JSON stream)

# Sessions
bash runner/harness.sh session new --user ops --workspace local
bash runner/harness.sh session say <session_id> "Hello"
bash runner/harness.sh session list

# Raw CLI passthrough (always runs with the same runner env)
bash runner/harness.sh shisad <any shisad args...>
```
