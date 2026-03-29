# Runner Harness — Operator Runbook

This is the default operator runbook for the `runner/` harness. It covers
the common bring-up, verification, and teardown workflow that applies to
**any** version of shisad during local development.

For current public operator guidance, see:

- `docs/DEPLOY.md` — bring-up, credentials, and local daemon workflow
- `docs/ROADMAP.md` — current public milestone framing

---

## Preconditions

- You are in the `shisad` repo root.
- Python deps are installed (`uv sync --dev`).
- If you want live remote planner calls, the right API key is set for your
  preset (see *Credentials* below).
- If using coding-agent workflows (`shisad dev ...`), at least one agent CLI
  is installed and authenticated in the shell environment.

## Credentials

The harness loads secrets from two sources (later overrides earlier):

1. **`SHISAD_ENV_FILE`** — canonical system/user env file
   (e.g. `~/.config/shisad/runtime.env`). Set this in your shell profile.
2. **`runner/.env`** — repo-local dev overrides (gitignored).
   Copy `runner/.env.example` and fill in values.

Planner preset → required key:

| Preset | Key |
|---|---|
| `shisa_default` | `SHISA_API_KEY` |
| `openai_default` | `OPENAI_API_KEY` |
| `openrouter_default` | `OPENROUTER_API_KEY` |
| `google_openai_default` | `GEMINI_API_KEY` |
| `vllm_local_default` | *(none)* |

## Quick Start

```bash
# Background (requires tmux):
bash runner/harness.sh start
bash runner/harness.sh status
bash runner/harness.sh logs --follow

# Foreground (no tmux required):
bash runner/harness.sh start --fg

# Or the thin shim:
./run.sh
```

## Health Checks

```bash
bash runner/harness.sh status
bash runner/harness.sh doctor all
```

## Sessions

```bash
sid=$(bash runner/harness.sh session new --user ops --workspace local)
bash runner/harness.sh session say "$sid" "hello"
bash runner/harness.sh session list
```

## Logs and Events

```bash
bash runner/harness.sh logs                # last 200 lines
bash runner/harness.sh logs --follow       # tail -f
bash runner/harness.sh events              # structured JSON stream
```

## Stop / Restart

```bash
bash runner/harness.sh stop
bash runner/harness.sh restart
```

## Isolated Dev Instances

To run a second harness instance without disturbing an existing daemon,
override the identity and path vars:

```bash
RUNNER_INHERIT_SHISAD_ENV=1 \
RUNNER_TMUX_SOCKET_NAME=shisad-feature \
RUNNER_TMUX_SESSION_NAME=shisad-feature \
SHISAD_DATA_DIR=/tmp/shisad-feature-data \
SHISAD_SOCKET_PATH=/tmp/shisad-feature.sock \
SHISAD_POLICY_PATH=/tmp/shisad-feature-policy.yaml \
  bash runner/harness.sh start --no-debug
```

The `RUNNER_INHERIT_SHISAD_ENV=1` flag tells the harness to keep your
shell's `SHISAD_*` values instead of clearing them.

## Default Policy

If no policy file exists at `SHISAD_POLICY_PATH`, the harness copies
`runner/policy.default.yaml` as the initial policy. Edit the generated
file or provide your own for different postures.

## Common Failure Modes

- **Daemon not reachable after start**: check `bash runner/harness.sh logs`
  for startup errors (missing deps, port conflicts, bad config).
- **Credential preflight fails**: ensure the key for your planner preset
  is set in `SHISAD_ENV_FILE` or `runner/.env`.
- **tmux session already exists**: attach with
  `tmux -L shisad-dev attach -t shisad-dev` or stop first.
- **Autoreload restarts during long runs**: use `--no-debug` for stable
  drives where you are editing repo files concurrently.
