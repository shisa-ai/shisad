# Runner Harness (Live Daemon + CLI)

This file is the "how to operate shisad locally" playbook intended for agentic coders. The goal is that any coding agent can bootstrap a live daemon, inspect logs/events, and send messages or run admin workflows without guessing about env/config.

## What Lives Here

- `runner/harness.sh`: the one entrypoint. It sets a safe default env, starts/stops the daemon, tails logs, and wraps `uv run shisad ...` so the CLI always targets the same socket.
- `runner/policy.default.yaml`: bootstrap policy template; copied to `SHISAD_POLICY_PATH` when no policy file exists. Edit this template to change the default tool/capability posture for all new harness runs.
- `runner/.env.example`: template for private overrides (copy to `runner/.env`, which is gitignored).
- `.local/`: runtime artifacts (gitignored):
  - `.local/shisad-dev/daemon.log`, `.local/shisad-dev/daemon.pid`
  - `.local/policy.yaml` (auto-created from template if missing)

## Preconditions

- You are in the `shisad` repo root.
- Python deps are installed (example: `uv sync --dev`).
- If you want *live* remote planner calls, you have the right API key set for your preset (examples below).
- If you want to run `shisad dev implement/review/remediate`, at least one coding-agent CLI is installed and already authenticated in the *daemon's* environment (the daemon inherits your shell env when started).

## Secret and Env Loading

The harness loads env from two sources (later overrides earlier):

1. **`SHISAD_ENV_FILE`** — canonical system/user env file (e.g. `~/.config/shisad/runtime.env`). Set this var in your shell profile to point at your credentials file; the harness will parse it first.
2. **`runner/.env`** — repo-local dev overrides (gitignored). Copy `runner/.env.example` and fill in values. These override anything set via `SHISAD_ENV_FILE`.

Both files are parsed as data (no `source`); only `KEY=VALUE` lines are exported.

Supported formats:

- `KEY=value`
- `KEY="value"`
- `KEY='value'`

## Quickstart

Operator runbook: [`runner/RUNBOOK.md`](RUNBOOK.md).

Start a daemon and follow logs:

```bash
bash runner/harness.sh start
bash runner/harness.sh logs --follow
```

Background start uses `tmux` so the daemon survives across non-interactive shells. You can attach:

```bash
tmux -L shisad-dev attach -t shisad-dev
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

Run admin dev-loop commands:

```bash
bash runner/harness.sh shisad dev implement \
  "Implement the scoped task and keep it proposal-first." \
  --agent codex \
  --file-ref docs/ROADMAP.md
```

## Common Knobs

The harness sets defaults if you do not provide them:

- `SHISAD_DATA_DIR` (default: `.local/shisad-dev`)
- `SHISAD_SOCKET_PATH` (default: `/tmp/shisad-dev.sock`)
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

If your shell already has `SHISAD_*` configured for a separate "operator" daemon (Discord/Telegram/etc),
the runner harness will clear those inherited settings by default to keep runs local-only and deterministic.
To opt out (not recommended), set:

```bash
RUNNER_INHERIT_SHISAD_ENV=1
```

## Command Reference

```bash
# Daemon lifecycle
bash runner/harness.sh start            # start in background; logs to .local/shisad-dev/daemon.log
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

# Print effective env + paths
bash runner/harness.sh env
```
