# `runner/` (Agent Harness)

`runner/` is the checked-in harness for running a live local `shisad` daemon during development and letting agents (Codex, Claude, etc.) "take the wheel": start/restart the daemon, view logs/events, create sessions, and invoke `dev.*` workflows.

Quickstart (from repo root):

```bash
bash runner/harness.sh start
bash runner/harness.sh status
bash runner/harness.sh logs --follow
```

Talk to the daemon:

```bash
session_id="$(bash runner/harness.sh session new --user ops --workspace local)"
bash runner/harness.sh session say "$session_id" "Say hello in one short sentence."
```

Full mechanics (env/config, log locations, and all commands): see [`runner/SKILL.md`](SKILL.md).

Private local overrides (API keys, model presets, custom paths) go in `runner/.env` (gitignored). Start from `runner/.env.example`.

Current runbook: [`runner/RUNBOOK.md`](RUNBOOK.md) (symlink to the active M5 operator runbook).
