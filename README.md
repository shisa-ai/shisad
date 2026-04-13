# ShisaD (`shisad`)

[Security-first](docs/SECURITY.md) AI agent daemon framework.

ShisaD is a long-running daemon that sits between an LLM and external systems (tools, files, network, messaging channels). The model proposes actions; the runtime decides what actually executes — every tool call passes through policy enforcement, taint tracking, and audit before anything happens.

The core question at every action is: **who asked for it?** ShisaD is the user's agent — it exists to do what the user asks with the highest possible fidelity, and to prevent anything else (prompt injection, hallucination, attacker-controlled input) from taking control.

Rather than ignoring the elephant in the room, our design targets the [lethal trifecta](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/) head-on: agents that access private data, process untrusted content, and take consequential actions are inherently high-risk. Most agent security research solves this by removing capabilities until the agent is safe but useless. ShisaD takes the [opposite approach](docs/DESIGN-PHILOSOPHY.md): keep the agent fully capable and build enforcement infrastructure that makes each capability safe to use at runtime. If a tool is insecure, the goal is to fix the enforcement, not disable the tool.

```
                       ┌─────────────────┐
                       │   LLM (Planner) │
   Untrusted ────────▶│   [tokens mix]  │─────────▶ Proposed
   Content             │                 │            Actions
                       └─────────────────┘
                                                       │
   ═══════════════════════════════════════════════════════════
   ║               ARCHITECTURAL BOUNDARY                    ║
   ═══════════════════════════════════════════════════════════
                                                       │
                                                       ▼
                        ┌─────────────────┐     ┌─────────────┐
                        │ Trusted Config  │     │  Security   │
                        │ (policies,      │     │  Analyzers  │
                        │  goals)         │     │ (metadata   │
                        └─────────────────┘     │  only)      │
                                                └──────┬──────┘
                                                       ▼
                                                APPROVE / REJECT
```

## Features

- **COMMAND/TASK orchestration runtime** — persistent COMMAND sessions hand off delegated work to isolated TASK sessions with taint-safe summaries, approval provenance, and explicit task envelopes
- **Per-call policy enforcement** — 8-layer PEP pipeline (registry, schema, capability, DLP, resource authorization, egress allowlisting, credential scoping, taint sink enforcement) runs on every tool call, not just at session start
- **Taint-aware content handling** — ingress/egress content firewalls track provenance of untrusted input through the execution path
- **Confirmation gates, not blanket denial** — user-requested actions proceed; ambiguous or tainted actions route to confirmation; only genuine anomalies trigger lockdown
- **Behavioral anomaly detection** — control plane consensus (5 independent voters) for runtime anomaly detection, rate limiting, lockdown escalation, and operator-visible warnings on repeated suspicious deny patterns
- **Destructive command protection** — enforced at the sandbox policy layer before execution, not by LLM judgment; structurally incapable of `rm -rf /` regardless of prompt injection or misconfiguration
- **Clean-room workflows** — admin operations run in a taint-isolated session mode with no auto-apply
- **Multi-channel messaging** — Matrix, Discord, Telegram, Slack (Socket Mode), with default-deny identity allowlisting per channel
- **Assistant primitives** — notes/todos, scheduler with shared delivery, web search/fetch, baseline browser automation, filesystem/git helpers, and evidence references for large untrusted output
- **Artifact and evidence boundaries** — restart-stable evidence refs, structured ArtifactLedger storage, and terminal-safe evidence rendering keep large untrusted content off the raw prompt path by default
- **Intent-grounded execution** — risky actions must trace back to committed user or clean COMMAND intent, with missing-path reads routed to confirmation and missing-path side effects blocked
- **Provider routing** — pluggable LLM provider presets (Shisa, OpenAI, OpenRouter, Google, local vLLM) with per-route auth, model selection, and mixed-mode deployment
- **Tool-surface integrity** — reviewed local skills can declare tools, but their schema hashes are pinned across install/restart/runtime, drifted reviewed tools fail closed with explicit audit visibility, and dynamic remote tool discovery remains fail-closed
- **Observability** — comprehensive audit trail, TUI dashboard (pending actions, tasks, channel health, alerts), and `doctor` diagnostics

## Status

This repo is public and still pre-alpha. This tree contains the pre-publication
`v0.6.3` candidate content; published installability is determined by the
GitHub release tag and PyPI package. Live testing reopened the `v0.6.3`
release process for CLI trust and confirmation-flow fixes; this tree now
contains the recut candidate. Post-LT validation evidence is recorded for the
candidate line, and the follow-up LT5 live-retest reconciliation gate is green;
the release-close validation bundle is green; ReleaseClose reviewer sign-off and
explicit publication remain pending.

`v0.6.3` is the critical UX stabilization follow-up to `v0.6.2`: pending
confirmations now produce actionable daemon-owned replies, TOTP approvals can
be completed from trusted chat / command replies, TOTP enrollment can render a
terminal QR code, session-message output preserves line breaks, no-model and
startup diagnostics are clearer, and planner-visible tool surfaces better
reflect what is actually configured. The LT recut routes confirmation replies
as control commands before planner flow; LT5 live evidence is recorded for the
CLI-trust, stale pending-action, and low-risk internal bookkeeping portions of
that recut. Textual chat TUI newline rendering remains deferred to the TUI
overhaul. The next planned lane is `v0.6.4` for the `textguard` port after
`v0.6.3` closes.

| Version | Focus |
|---------|-------|
| **v0.6** | **Orchestration foundation + tool-surface expansion (COMMAND/TASK runtime, credential scoping, web tools, browser baseline)** |
| v0.5 | First public release — evidence references, repo split, zero-config SHISA provider |
| v0.4 | Self-modification, coding-agent runtime, COMMAND/TASK isolation |
| v0.3 | Provider routing, channels, assistant tools, destructive command protection |
| v0.2 | Structural refactor (typed handlers, decomposed runtime, coverage) |
| v0.1 | Core daemon, PEP security pipeline, control API |

This table tracks major release lines for operator orientation; patch releases
like `v0.5.1` and `v0.5.2` stay in the changelog rather than being listed here.

See [`docs/ROADMAP.md`](docs/ROADMAP.md) for more details.

## Getting Started

> `shisad` is currently **PRE-ALPHA** software and probably won't do what you think it will if you're not a developer. The easiest way to get setup is to point Claude Code, OpenAI Codex, or some other strong coding agent to install. When it's more baked, the installation procedure will be better.

Users and agents looking to set up ShisaD on their own system should see [`docs/DEPLOY.md`](docs/DEPLOY.md) for the full bring-up guide — host bootstrap, provider configuration, channel setup (Discord, Telegram, Slack), and troubleshooting. ShisaD is designed to run on a dedicated instance or container, not inside your development environment.

### Quick Start

```bash
git clone https://github.com/shisa-ai/shisad.git
cd shisad
uv sync --group dev --extra chat
```

YARA-backed content scanning is included in the base install through
`textguard[yara]`. For local PromptGuard runtime checks, add the security
runtime dependency group:

```bash
uv sync --group security-runtime --group dev --extra chat
```

`security-runtime` is a uv dependency group, not a pip extra; use `--group
security-runtime`, not `--extra security-runtime`. The `chat` package set is
the optional extra and uses `--extra chat`.

### Configuration

Environment variables use `SHISAD_` prefixes. Full reference: `docs/ENV-VARS.md`.

**Recommended: use the runner harness** for local development. It handles env isolation, secret loading, and policy bootstrapping:

```bash
bash runner/harness.sh start       # background (requires tmux)
bash runner/harness.sh start --fg  # foreground
bash runner/harness.sh status
```

See `runner/README.md` for details. Secrets go in `runner/.env` (gitignored) or `SHISAD_ENV_FILE`.

### Manual baseline

```bash
export SHISAD_DATA_DIR="$HOME/.local/share/shisad"
export SHISAD_SOCKET_PATH="/tmp/shisad/control.sock"
export SHISAD_POLICY_PATH="$PWD/.local/policy.yaml"
export SHISAD_LOG_LEVEL="INFO"
```

### Provider routing

Default (Shisa.AI):

```bash
# Planner route remote-enables implicitly when SHISA key resolves.
export SHISA_API_KEY="<shisa-api-key>"
```

OpenAI:

```bash
export SHISAD_MODEL_REMOTE_ENABLED=true
export OPENAI_API_KEY="<openai-api-key>"
export SHISAD_MODEL_PLANNER_PROVIDER_PRESET="openai_default"
export SHISAD_MODEL_PLANNER_MODEL_ID="gpt-5.4-2026-03-05"
# Optional: export SHISAD_MODEL_PLANNER_REQUEST_PARAMETERS='{"max_completion_tokens":512}'
```

OpenRouter:

```bash
export SHISAD_MODEL_REMOTE_ENABLED=true
export OPENROUTER_API_KEY="<openrouter-api-key>"
export SHISAD_MODEL_PLANNER_PROVIDER_PRESET="openrouter_default"
export SHISAD_MODEL_PLANNER_MODEL_ID="qwen/qwen3.5-397b-a17b"
export SHISAD_MODEL_PLANNER_EXTRA_HEADERS='{"HTTP-Referer":"https://example.com","X-Title":"shisad"}'
```

Google (OpenAI-compatible):

```bash
export SHISAD_MODEL_REMOTE_ENABLED=true
export GEMINI_API_KEY="<gemini-api-key>"
export SHISAD_MODEL_PLANNER_PROVIDER_PRESET="google_openai_default"
export SHISAD_MODEL_PLANNER_MODEL_ID="gemini-3.1-pro-preview"
```

Local vLLM:

```bash
export SHISAD_MODEL_PLANNER_PROVIDER_PRESET="vllm_local_default"
export SHISAD_MODEL_PLANNER_BASE_URL="http://127.0.0.1:8000/v1"
export SHISAD_MODEL_PLANNER_REMOTE_ENABLED=true
export SHISAD_MODEL_PLANNER_AUTH_MODE="none"
```

Mixed mode (planner remote, embeddings local, monitor remote):

```bash
export SHISAD_MODEL_REMOTE_ENABLED=true

export SHISAD_MODEL_PLANNER_PROVIDER_PRESET="openrouter_default"
export SHISAD_MODEL_PLANNER_MODEL_ID="qwen/qwen3.5-397b-a17b"
export SHISAD_MODEL_PLANNER_API_KEY="<planner-openrouter-key>"

export SHISAD_MODEL_EMBEDDINGS_PROVIDER_PRESET="vllm_local_default"
export SHISAD_MODEL_EMBEDDINGS_BASE_URL="http://127.0.0.1:8000/v1"
export SHISAD_MODEL_EMBEDDINGS_REMOTE_ENABLED=true
export SHISAD_MODEL_EMBEDDINGS_AUTH_MODE="none"
export SHISAD_MODEL_EMBEDDINGS_MODEL_ID="text-embedding-3-small"

export SHISAD_MODEL_MONITOR_PROVIDER_PRESET="openai_default"
export SHISAD_MODEL_MONITOR_API_KEY="<monitor-openai-key>"
export SHISAD_MODEL_MONITOR_MODEL_ID="gpt-5.4-2026-03-05"
```

Verify provider setup:

```bash
uv run shisad doctor check --component provider
```

Auth notes:
- Use `*_auth_mode=header` when custom auth header names are required.
- `*_auth_header_name` is not accepted for `*_auth_mode=bearer|none`.

### Channels

```bash
export SHISAD_DISCORD_ENABLED=true
export SHISAD_DISCORD_BOT_TOKEN="<token>"

export SHISAD_TELEGRAM_ENABLED=true
export SHISAD_TELEGRAM_BOT_TOKEN="<token>"

export SHISAD_SLACK_ENABLED=true
export SHISAD_SLACK_BOT_TOKEN="<xoxb-token>"
export SHISAD_SLACK_APP_TOKEN="<xapp-token>"

# Default-deny allowlist: channel -> [external_user_id]
export SHISAD_CHANNEL_IDENTITY_ALLOWLIST='{"discord":["1234567890"],"telegram":["11111"],"slack":["U12345"]}'
```

### Assistant surfaces

```bash
# web_fetch and web_search are enabled by default.
# web_search needs a compatible JSON search backend (SearxNG-style /search?q=...&format=json).
# The backend host must also be present in SHISAD_WEB_ALLOWED_DOMAINS.
export SHISAD_WEB_SEARCH_BACKEND_URL="https://search.example.com"
export SHISAD_WEB_ALLOWED_DOMAINS='["search.example.com","docs.example.com"]'

# Verify the configured tool surface from a live daemon:
# uv run python scripts/live_tool_matrix.py --tool-status

# Optional: browser automation baseline (read-mostly navigation plus
# confirmation-gated write actions) via a Playwright-compatible CLI wrapper.
export SHISAD_BROWSER_ENABLED=true
export SHISAD_BROWSER_COMMAND="/path/to/playwright-cli"
export SHISAD_BROWSER_ALLOWED_DOMAINS='["example.com"]'

export SHISAD_ASSISTANT_FS_ROOTS='["/tmp/shisad-workspace"]'
```

## Usage

### Start and verify

```bash
uv run shisad start --foreground
```

In another shell:

```bash
uv run shisad status
uv run shisad doctor check --component all
uv run shisad tui --plain
```

### Sessions

```bash
uv run shisad session create --user alice --workspace demo
uv run shisad session list
uv run shisad session message <session-id> "summarize current priorities"
```

### Notes and todos

```bash
uv run shisad note create --key ops/runbook --content "verify doctor before deploy"
uv run shisad note list
uv run shisad todo create --title "close rollout checklist" --status open
uv run shisad todo list
```

### Web and filesystem

```bash
uv run shisad web search "shisad security architecture" --limit 5
uv run shisad web fetch https://example.com
uv run shisad fs read /tmp/shisad-workspace/notes.txt
uv run shisad fs write /tmp/shisad-workspace/out.txt --content "hello" --confirm
uv run shisad git status --repo /tmp/shisad-workspace
```

### Admin clean-room

```bash
uv run shisad session mode <session-id> --mode admin_cleanroom
uv run shisad channel pairing-propose --limit 50
```

## Security Model

shisad assumes prompt injection will succeed and builds enforcement outside the model. The LLM is a planner, not an executor — it proposes tool calls, but the runtime pipeline decides whether each call proceeds, requires confirmation, or gets blocked. No amount of prompt injection, jailbreaking, or misconfiguration can override the enforcement layers because they run in a separate trust domain from the model.

**The problem**: any agent with access to private data (files, email), exposure to untrusted content (web pages, API responses), and the ability to take consequential actions (send messages, write files) is exploitable. This is the [lethal trifecta](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/). shisad has all three by design — it's meant to be a useful assistant, not a sandboxed demo.

**The approach**: instead of removing capabilities until the agent is safe (at which point you've rebuilt ChatGPT with extra steps), shisad keeps all capabilities available and enforces safety per-call:

- **8-layer PEP pipeline** on every tool call: registry check, schema validation, capability check, DLP (secret pattern detection), resource authorization, egress allowlisting, credential host-scoping, taint sink enforcement
- **Taint tracking**: content firewalls tag untrusted input on ingress and enforce provenance-aware restrictions on egress — the runtime knows *who asked for* each action (user vs. injected content vs. model hallucination)
- **Confirmation gates**: user-requested actions proceed; actions with ambiguous or tainted provenance route to user confirmation with context; only genuine anomalies trigger lockdown
- **Behavioral anomaly detection**: control plane consensus (5 independent voters) catches patterns that individual call-level checks miss
- **Destructive command protection**: enforced at the sandbox layer before execution, not by LLM judgment — structurally incapable of `rm -rf /` regardless of what the model is tricked into proposing

**Default posture**: all tools available out of the box. Operators who need a restrictive posture deploy an explicit policy via `SHISAD_POLICY_PATH`.

**Egress model**: allowlists auto-approve known-good destinations. Explicit user requests proceed without confirmation. Destinations suggested only by untrusted content route through confirmation with warning. Unattributed/hallucinated drift is blocked.

See `docs/SECURITY.md` for the full security architecture and `docs/DESIGN-PHILOSOPHY.md` for the governing principles.

## Architecture

```
shisad/
├── src/shisad/          # Core source
│   ├── daemon/          # Control API, handlers, runtime implementation
│   ├── security/        # PEP pipeline, content firewalls, taint tracking
│   ├── executors/       # Tool execution, egress proxy
│   ├── channels/        # Matrix, Discord, Telegram, Slack
│   ├── assistant/       # Notes, todos, web, fs/git tools
│   ├── memory/          # Structured storage with semantic search
│   ├── scheduler/       # Task scheduling and delivery
│   ├── cli/             # Click-based CLI
│   ├── ui/              # TUI dashboard
│   ├── skills/          # Hot-reloadable skill plugins
│   └── governance/      # Anomaly voting, consensus
├── tests/
│   ├── unit/            # Component tests
│   ├── integration/     # Cross-component runtime flows
│   ├── behavioral/      # Product-correctness gate
│   └── adversarial/     # Prompt injection, exfil, evasion
├── runner/              # Dev harness (tmux, env isolation, policy bootstrap)
├── scripts/             # Validation, coverage, asset checks
├── docs/                # Design docs, ADRs, runbooks, analysis
└── examples/            # Example configs and skills
```

Key runtime paths:
- Policy enforcement: `src/shisad/security/pep.py`
- Egress proxy: `src/shisad/executors/proxy.py`
- Handler implementation: `src/shisad/daemon/handlers/_impl.py` (composed from `_impl_session.py`, `_impl_tool_execution.py`, `_impl_memory.py`, etc.)

## Development

```bash
uv run ruff check src/ tests/ scripts/
uv run mypy src/shisad/
uv run pytest -q
```

See `AGENTS.md` for full development process, validation matrix, and commit conventions.

## Documentation

| Doc | Description |
|-----|-------------|
| `docs/DESIGN-PHILOSOPHY.md` | First-principles reference — read this first |
| `docs/DEPLOY.md` | Public bring-up and deployment quickstart |
| `docs/SECURITY.md` | Security architecture — threat model, enforcement layers, trust boundaries |
| `docs/ROADMAP.md` | Public roadmap and milestone direction |
| `docs/USE-CASES.md` | Prioritized use cases and capability mapping |
| `docs/ENV-VARS.md` | Environment variable reference |
| `docs/TOOL-STATUS.md` | Current tool surface snapshot |
| `docs/adr/` | Architectural decision records |
| `docs/analysis/` | Security case studies and supply chain analysis |
| `docs/runbooks/` | Operator runbooks (incident response, key rotation, rollback, skill revocation) |
| `runner/RUNBOOK.md` | Dev harness operator runbook |

- [agentic-security](https://github.com/lhl/agentic-security) — literature survey on LLM agent security (78 papers, defense taxonomy, production readiness assessment)
- [agentic-memory](https://github.com/lhl/agentic-memory) — literature survey on agent memory architectures and poisoning defenses (29+ references, attack taxonomy, defense recommendations)

## License

Apache License 2.0. See `LICENSE`.
