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
- Python deps are installed. The standard source-checkout path is
  `uv sync --group dev --extra chat`, which uses the repo `.venv`.
  For an existing conda/mamba env, install `uv` in that env, then run
  `uv export --frozen --format requirements.txt --group dev --extra chat`
  and `uv pip install --python "$CONDA_PREFIX/bin/python" -r <requirements>
  --strict`, followed by an editable install of the checkout.
  For local PromptGuard/YARA runtime checks, use
  `uv sync --group security-runtime --group dev --extra chat`.
  `security-runtime` is a dependency group, not an extra; `chat` is the extra.
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
bash runner/harness.sh shisad status
bash runner/harness.sh logs --follow

# Foreground (no tmux required):
bash runner/harness.sh start --fg

# Or the thin shim:
./run.sh
```

The harness and plain `shisad` use the same per-user default socket. After
starting with `./run.sh` or `bash runner/harness.sh start`, another terminal
can run `shisad status` or `shisad chat` without setting `SHISAD_SOCKET_PATH`.

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

## Web Search Backend

`tool.web.search` needs an external JSON search backend (SearxNG-style
`/search?q=...&format=json`). If `SHISAD_WEB_SEARCH_BACKEND_URL` is unset,
the tool reports `web_search_backend_unconfigured` in doctor output and
returns no results — research-shaped prompts will degrade accordingly.

For local development, first start a loopback-only SearxNG instance with JSON
responses enabled. The full Docker recipe and troubleshooting table live in
`docs/DEPLOY.md`.

Minimum `runner/.env` config for that local SearxNG setup:

```env
SHISAD_WEB_SEARCH_ENABLED=true
SHISAD_WEB_SEARCH_BACKEND_URL=http://127.0.0.1:8080
SHISAD_WEB_ALLOWED_DOMAINS=127.0.0.1,localhost
```

IP-literal, `localhost`, and `.local` / `.internal` / `.lan` backend hosts need
to be in the effective web allowlist. For this runner setup, set that list with
`SHISAD_WEB_ALLOWED_DOMAINS`; the local recipe above uses
`127.0.0.1,localhost` for that reason. If the variable is unset, the daemon
falls back to policy egress hosts. Restart the daemon after changing
`SHISAD_WEB_*` values; exporting them in a separate CLI terminal does not update
an already-running daemon.

```bash
bash runner/harness.sh stop
bash runner/harness.sh start --no-debug
bash runner/harness.sh shisad web search "latest Python release" --limit 3
```

See `docs/DEPLOY.md` for the operator-level overview and `docs/ENV-VARS.md`
for the full variable reference.

## Default Policy

If no policy file exists at `SHISAD_POLICY_PATH`, the harness copies
`runner/policy.default.yaml` as the initial policy. Edit the generated
file or provide your own for different postures.

## Common Failure Modes

- **Daemon not reachable after start**: check `bash runner/harness.sh logs`
  for startup errors (missing deps, port conflicts, bad config).
- **Search returns `web_search_backend_unconfigured`**:
  `SHISAD_WEB_SEARCH_BACKEND_URL` is missing from the daemon environment.
  Add it to `SHISAD_ENV_FILE` or `runner/.env`, then restart the daemon.
- **Search returns `search_backend_invalid_json`**: verify the backend directly
  with `curl 'http://127.0.0.1:8080/search?q=shisad&format=json'`; for SearxNG,
  make sure `json` is listed under `search.formats`.
- **Search fails with `ip_literal_not_allowlisted` or
  `local_destination_not_allowlisted`**: add the backend host to
  `SHISAD_WEB_ALLOWED_DOMAINS` for runner/env-file setups, or to policy egress
  hosts when using policy fallback, then restart the daemon.
- **Credential preflight fails**: ensure the key for your planner preset
  is set in `SHISAD_ENV_FILE` or `runner/.env`.
- **tmux session already exists**: attach with
  `tmux -L shisad-dev attach -t shisad-dev` or stop first.
- **Autoreload restarts during long runs**: use `--no-debug` for stable
  drives where you are editing repo files concurrently.
