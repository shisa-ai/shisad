# `runner/` (Dev Harness)

`runner/` is the canonical harness for running a live local `shisad` daemon during development. It handles env isolation, secret loading, policy bootstrapping, and daemon lifecycle so that humans and agentic coders get deterministic, safe-by-default local runs.

Quickstart (from repo root):

```bash
bash runner/harness.sh start       # background; requires tmux
bash runner/harness.sh start --fg  # foreground; no tmux required
bash runner/harness.sh status
bash runner/harness.sh logs --follow
```

Background start uses `tmux` so the daemon survives across non-interactive shells.
For long live drives after repo edits, prefer `bash runner/harness.sh start --no-debug`
so autoreload does not restart the daemon mid-run.

Talk to the daemon:

```bash
session_id="$(bash runner/harness.sh session new --user ops --workspace local)"
bash runner/harness.sh session say "$session_id" "Say hello in one short sentence."
```

## File Layout

| File | Purpose |
|---|---|
| `harness.sh` | Single entrypoint for all runner operations |
| `daemon_entrypoint.sh` | Internal tmux launch wrapper |
| `policy.default.yaml` | Bootstrap policy template (copied when no policy exists) |
| `.env.example` | Template for repo-local secret overrides |
| `RUNBOOK.md` | Operator runbook (version-agnostic; references versioned docs) |
| `SKILL.md` | Full playbook for agentic coders |

## Secrets and Env

The harness loads env from two sources (later overrides earlier):

1. **`SHISAD_ENV_FILE`** — canonical system/user env (e.g. `~/.config/shisad/runtime.env`)
2. **`runner/.env`** — repo-local dev overrides (gitignored)

Copy `runner/.env.example` to `runner/.env` for local-only values.

The harness clears inherited `SHISAD_*` env by default so it does not accidentally start with a preconfigured operator daemon (Discord/Telegram/etc). Set `RUNNER_INHERIT_SHISAD_ENV=1` to opt out.

Full mechanics (env/config, log locations, all commands): see [`runner/SKILL.md`](SKILL.md).

Operator runbook: [`runner/RUNBOOK.md`](RUNBOOK.md).
