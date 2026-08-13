# ShisaD (`shisad`)

[Security-first](docs/SECURITY.md) AI agent daemon framework.

ShisaD is a long-running daemon that sits between an LLM and external systems
(tools, files, network, messaging channels). The model proposes actions; the
shared planner execution path decides what actually executes through policy
enforcement, provenance/taint checks, confirmation, and audit. Authenticated
operator convenience RPCs are separate routes with route-local validation and
logging; see the [ref-scoped authority map](docs/AUTHORITY-MAP.md) for the exact
boundary.

The core question at every action is: **who asked for it?** ShisaD is the user's agent — it exists to do what the user asks with the highest possible fidelity, and to prevent anything else (prompt injection, hallucination, attacker-controlled input) from taking control.

Rather than ignoring the elephant in the room, our design targets the [lethal trifecta](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/) head-on: agents that access private data, process untrusted content, and take consequential actions are inherently high-risk. Most agent security research solves this by removing capabilities until the agent is safe but useless. ShisaD takes the [opposite approach](docs/DESIGN-PHILOSOPHY.md): keep the agent fully capable and build enforcement infrastructure that makes each capability safe to use at runtime. If a tool is insecure, the goal is to fix the enforcement, not disable the tool.

```
                       ┌─────────────────┐
                       │   LLM (Planner) │
   Untrusted ─────────►│   [tokens mix]  │─────────► Proposed
   Content             │                 │            Actions
                       └─────────────────┘
                                                       │
   ═══════════════════════════════════════════════════════════
   ║               ARCHITECTURAL BOUNDARY                    ║
   ═══════════════════════════════════════════════════════════
                                                       │
                                                       ▾
                        ┌─────────────────┐     ┌─────────────┐
                        │ Trusted Config  │     │  Security   │
                        │ (policies,      │     │  Analyzers  │
                        │  goals)         │     │ (metadata   │
                        └─────────────────┘     │  only)      │
                                                └──────┬──────┘
                                                       ▾
                                                APPROVE / REJECT
```

## Features

- **Structured long-term memory** — separate identity, active-attention, recall, procedural, and evidence surfaces share a versioned local store with provenance-gated writes, review gates for high-risk paths, and auditable provenance
- **COMMAND/TASK orchestration runtime** — persistent COMMAND sessions hand off delegated work to isolated TASK sessions with taint-safe summaries, approval provenance, and explicit task envelopes
- **Per-call policy enforcement** — the 8-layer PEP pipeline (registry, schema, capability, DLP, resource authorization, egress allowlisting, credential scoping, taint sink enforcement) runs on every shared planner / `tool.execute` action, not just at session start
- **Taint-aware content handling** — ingress/egress content firewalls track provenance of untrusted input through the execution path
- **Confirmation gates, not blanket denial** — user-requested actions proceed; ambiguous or tainted actions route to confirmation; only genuine anomalies trigger lockdown
- **Command-channel approvals** — supported command surfaces can approve or reject routine pending actions where they originated, with CLI remaining as fallback rather than the only path
- **Behavioral anomaly detection** — control plane consensus (5 independent voters) for runtime anomaly detection, rate limiting, lockdown escalation, and user-visible warnings on repeated suspicious deny patterns
- **Destructive command protection** — under the supported containment profile,
  command policy is enforced before execution rather than by LLM judgment;
  unavailable required isolation fails closed, while the explicit
  `expert_host_fallback` posture carries no supported-containment claim
- **Clean-room workflows** — admin operations run in a taint-isolated session mode with no auto-apply
- **Multi-channel messaging** — Matrix, Discord, Telegram, Slack (Socket Mode), with default-deny identity allowlisting per channel
- **Assistant primitives** — notes/todos, scheduler with shared delivery, web search/fetch, baseline browser automation, filesystem/git helpers, and evidence references for large untrusted output
- **Artifact and evidence boundaries** — restart-stable evidence refs, structured ArtifactLedger storage, and terminal-safe evidence rendering keep large untrusted content off the raw prompt path by default
- **Intent-grounded execution** — risky actions must trace back to committed user or clean COMMAND intent, with missing-path reads routed to confirmation and missing-path side effects blocked
- **Provider routing** — pluggable LLM provider presets (Shisa, OpenAI, OpenRouter, Google, local vLLM) with per-route auth, model selection, and mixed-mode deployment
- **Tool-surface integrity** — reviewed local skills can declare tools, but their schema hashes are pinned across install/restart/runtime, drifted reviewed tools fail closed with explicit audit visibility, and dynamic remote tool discovery remains fail-closed
- **Observability** — comprehensive audit trail, TUI dashboard (pending actions, tasks, channel health, alerts), and `doctor` diagnostics

## Status

This repo is public and still pre-alpha. The latest published stable line is
`v0.8.1`. The `v0.8.0b1` beta checkpoint remains available for users who need
the prerelease structured-authorization checkpoint.

| Version | Focus |
|---------|-------|
| v0.8.2 (development) | Reliability fixes, a read-only bare-command preflight, and provider-agnostic credential references; the combined setup wizard and lifecycle routing remain in progress |
| v0.8.1 | Package/config UX plus durable action attempts, restart-safe finite state, containment boundaries, and four-channel delivery/approval continuity |
| v0.8.0 | Command-channel approvals, TUI/confirmation polish, task panels, and stable UX-overhaul foundation |
| v0.8 beta | Bug-fix checkpoint before the stable UX overhaul (latest beta: `v0.8.0b1`) |
| v0.7 | Memory foundation + long-term memory/evaluation surfaces (latest published: `v0.7.4`) |
| v0.6 | Orchestration foundation + tool-surface expansion (COMMAND/TASK runtime, credential scoping, web tools, browser baseline) |
| v0.5 | First public release — evidence references, repo split, zero-config SHISA provider |
| v0.4 | Self-modification, coding-agent runtime, COMMAND/TASK isolation |
| v0.3 | Provider routing, channels, assistant tools, destructive command protection |
| v0.2 | Structural refactor (typed handlers, decomposed runtime, coverage) |
| v0.1 | Core daemon, PEP security pipeline, control API |

This table tracks major release lines for reader orientation; patch releases
like `v0.5.1` and `v0.5.2` stay in the changelog rather than being listed here.

See [`docs/ROADMAP.md`](docs/ROADMAP.md) for more details.

## Getting Started

> `shisad` is currently **PRE-ALPHA** software and probably won't do what you think it will if you're not a developer. The easiest way to get setup is to point Claude Code, OpenAI Codex, or some other strong coding agent to install. When it's more baked, the installation procedure will be better.

Users and agents looking to set up ShisaD on their own system should see [`docs/DEPLOY.md`](docs/DEPLOY.md) for the full bring-up guide — host bootstrap, provider configuration, channel setup (Discord, Telegram, Slack, Matrix), and troubleshooting. ShisaD is designed to run on a dedicated instance or container, not inside your development environment.

### Quick Start

For `v0.8.1` artifacts, install the complete assistant runtime rather than a
source checkout:

```bash
uv tool install 'shisad[assistant]'
shisad --help
shisad doctor check --component all
```

The `assistant` extra contains the Textual UI plus MCP, Matrix E2EE, Discord,
Telegram, and Slack client runtimes. It does not enable channels or add
credentials; those remain explicit configuration. PromptGuard also remains a
separate opt-in, so install `shisad[assistant,promptguard]` only when that local
model runtime is wanted. The latest currently published package is `v0.8.0`;
the `assistant` extra becomes a PyPI install surface when `v0.8.1` is actually
published.

This repository also contains a tested Linux/amd64 Dockerfile candidate. No
registry image is published or signed from this tree yet; build it locally and
follow the volume, policy, and isolation checks in
[`docs/DEPLOY.md`](docs/DEPLOY.md#local-container-candidate-v081).

### Development checkout

Use a source checkout for development and test groups:

```bash
git clone https://github.com/shisa-ai/shisad.git
cd shisad
uv --no-config sync --frozen --group dev --group channels-runtime
```

YARA-backed content scanning is included in the base install through
`textguard[yara]`. For local PromptGuard runtime checks from a source checkout,
add the security runtime dependency group:

```bash
uv --no-config sync --frozen --group security-runtime --group dev --extra chat
```

`--no-config --frozen` makes source setup consume the repository's reviewed
lock instead of silently replacing it with discovered user/system uv config.
Explicit `UV_*` environment variables and command-line overrides remain
caller-owned and should be cleared when they conflict with this setup path.
If your environment intentionally enforces a different package-age cutoff, it
must admit every security floor in `pyproject.toml`; do not lower those floors
or narrow supported Python versions to make a stale package universe resolve.

For package installs, use the first-class PromptGuard extra, for example
`uv pip install 'shisad[promptguard]'`. `security-runtime` is a uv dependency
group, not a pip extra; use `--group security-runtime`, not
`--extra security-runtime`. The `assistant`, `chat`, and `promptguard` package
sets are project optional extras; `assistant` is the complete consumer profile,
while `chat` remains the smaller Textual-only profile.

Memory retrieval prefers Python's `sqlite3` runtime to have SQLite FTS5
enabled. shisad falls back when FTS5 is unavailable, but you should verify the
preferred path with `uv run shisad doctor check --component storage`; see
[`docs/runbooks/SQLITE.md`](docs/runbooks/SQLITE.md) for install guidance.

### Configuration

Environment variables use `SHISAD_` prefixes. Full reference: `docs/ENV-VARS.md`.

The current v0.8.2 development CLI can inspect the environment and create or
inspect the typed TOML surface without starting the daemon:

```bash
shisad
shisad init
shisad config validate
shisad config show --format human
shisad config diff --format human
shisad config schema --format json
shisad env --format human
shisad credential status model.primary
```

Bare `shisad` is a read-only welcome and preflight. It distinguishes fresh,
returning, explicitly managed, and non-interactive posture from finite machine
facts; reports required, optional/degraded, and informational checks; and names
an explicit next action. It does not prompt, write configuration, migrate a
schema, start the daemon, or open chat. Unsupported config schema and invalid
managed posture fail actionably instead of inferring consent. The guided setup
wizard and automatic first-start/chat routing remain later v0.8.2 work.

`shisad init` creates one owner-only commented template at
`$XDG_CONFIG_HOME/shisad/config.toml` (normally
`~/.config/shisad/config.toml`) and refuses an existing or symlink destination.
It is deliberately not a setup wizard: it does not copy ambient secrets,
configure a provider or policy, create daemon state, or start the daemon. Use
root `--config FILE` to select another path. Effective precedence remains
command-line override, environment, TOML, then typed default; show, diff, env,
and validation output redact secret-bearing fields.

The O2 credential foundation can keep model-provider secrets out of TOML. A
logical reference records only backend metadata; the value stays in an
environment variable, an optional OS keyring, or a permission-protected local
plaintext file:

```bash
# Metadata only: this never copies or prints OPENAI_API_KEY.
shisad credential set model.primary --backend env --locator OPENAI_API_KEY

# Or enroll a local owner-only file value through stdin, never argv.
printf '%s' "$PROVIDER_KEY" |
  shisad credential set model.primary --backend file --stdin

# Point model config at the logical name.
# [model]
# remote_enabled = true
# api_key_ref = "model.primary"

shisad credential status model.primary --format human
shisad credential remove model.primary
```

The local file backend is plaintext at rest protected by `0700` directories
and `0600` files; it is not described as encrypted. Install
`shisad[credentials]` to enable the maintained Python keyring integration. An
unavailable keyring fails actionably and never falls back to a file. Generated
setup/config output persists references, not values. Existing explicit raw
model-key fields remain compatible, but a route cannot configure both a raw
key and a reference. A reference supplies a credential; it does not bypass the
existing `remote_enabled` posture.

Chat, the one-shot terminal dashboard, and the static web snapshot share the
three built-in palettes `shisa-dark`, `shisa-light`, and
`shisa-high-contrast`. Select one with `SHISAD_UI_THEME`, disable optional
motion with `SHISAD_REDUCE_MOTION=true`, and suppress palette color with
`NO_COLOR` or a root flag such as `shisad --no-color tui`. Custom theme-file
selection is not a supported configuration surface. `shisad web-ui` writes a
local static investigation/export artifact; it is not the planned live
operator web application. The artifact embeds session, pending-action, alert,
and egress-review data, so keep it private and remove it when the investigation
is complete.

Expected CLI failures use exit status 1 for command/user-state errors, 2 for
daemon-connect/RPC errors (and Click usage compatibility), and 3 for invalid or
unsafe configuration; success is 0. `doctor` remains read-only and has no
automatic `--fix` mode. Root help advertises the canonical `reality-check`
spelling while the legacy `realitycheck` spelling remains a hidden
compatibility alias.

**Recommended: use the runner harness** for local development. It handles env isolation, secret loading, and policy bootstrapping:

```bash
bash runner/harness.sh start       # background (requires tmux)
bash runner/harness.sh start --fg  # foreground
bash runner/harness.sh status
bash runner/harness.sh shisad status
```

The runner and plain `shisad` use the same per-user default socket, so another
terminal can run `shisad status` or `shisad chat` without exporting
`SHISAD_SOCKET_PATH`. See `runner/README.md` for details. Secrets go in
`runner/.env` (gitignored) or `SHISAD_ENV_FILE`.

### Manual baseline

```bash
export SHISAD_DATA_DIR="$HOME/.local/share/shisad"
case "${XDG_RUNTIME_DIR:-}" in
  /*) export SHISAD_SOCKET_PATH="$XDG_RUNTIME_DIR/shisad/control.sock" ;;
  *) export SHISAD_SOCKET_PATH="/tmp/shisad-$(id -u)/control.sock" ;;
esac
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
# IP-literal, localhost, and .local/.internal/.lan backends must be in the effective web allowlist.
# Set SHISAD_WEB_ALLOWED_DOMAINS for that list; if unset, daemon policy egress hosts are used.
# Public backend hosts can be listed to preapprove backend redirects and related fetches.
# For local SearxNG setup, see docs/DEPLOY.md#web-search-backend-recommended.
export SHISAD_WEB_SEARCH_BACKEND_URL="https://search.example.com"
export SHISAD_WEB_ALLOWED_DOMAINS='["search.example.com","docs.example.com"]'

# Verify the configured tool surface from a live daemon:
# uv run python scripts/live_tool_matrix.py --tool-status

# Optional: browser automation baseline (read-mostly navigation plus
# confirmation-gated write actions). The built wheel does not install this
# source-checkout wrapper; package installs need an explicit compatible wrapper.
export SHISAD_BROWSER_ENABLED=true
export SHISAD_BROWSER_COMMAND="/path/to/shisad/scripts/shisad-playwright-cli.mjs"
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
uv run shisad doctor check --component storage
uv run shisad tui --plain
```

### Sessions

```bash
uv run shisad session create --user alice --workspace demo
uv run shisad session list
uv run shisad session message <session-id> "summarize current priorities"
```

Session-derived conversation summaries can create durable memory entries by
default when the session has `memory.write`; resulting writes are owner-scoped
when the session has a complete `--user` / `--workspace` owner tuple. For clean
demos or workspaces where ordinary chat should not create automatic memory, set
`SHISAD_MEMORY_AUTO_EXTRACTION_ENABLED=false`. Operators can also raise
`SHISAD_MEMORY_AUTO_EXTRACTION_CONFIDENCE_THRESHOLD` from `0` toward `1` to keep
only higher-confidence automatic extraction proposals.

### Timeline search

```bash
uv run shisad memory timeline search "what did we decide last week?" --user alice --workspace demo
uv run shisad memory timeline read <timeline-handle> --user alice --workspace demo
uv run shisad memory timeline promote <timeline-handle> --type fact --key project/decision --user alice --workspace demo
```

Timeline search is explicit-pull only. Results are archival evidence from prior
session transcripts, not current user instructions, and shared/public channel
contexts do not reveal owner-private history unless private history is
explicitly allowed for that request. Read packets include role, source surface,
provenance, taints, evidence refs, and content digests; search/read/promote
decisions are recorded in the audit log without raw query or snippet text. For
shared-channel contexts, pass the concrete room binding with `--recipient`,
`--workspace-hint`, and `--thread-id` so same-connector/different-room history
stays isolated.

### Notes and todos

```bash
uv run shisad note create --key ops/runbook --content "verify doctor before deploy" --user alice --workspace demo
uv run shisad note list --user alice --workspace demo
uv run shisad todo create --title "close rollout checklist" --status open --user alice --workspace demo
uv run shisad todo list --user alice --workspace demo
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
uv run shisad channel pairing-propose --workspace <provider-workspace> --limit 50
```

## Security Model

shisad assumes prompt injection will succeed and builds enforcement outside the
model. On the shared planner path, the LLM is a planner, not an executor: it
proposes tool calls, while runtime enforcement decides whether each call
proceeds, requires confirmation, or is blocked. Those enforcement decisions do
not come from the model. Authenticated local operator convenience RPCs do not
claim the same PEP/control-plane path; their exact route-local boundaries are
listed in [`docs/AUTHORITY-MAP.md`](docs/AUTHORITY-MAP.md).

**The problem**: any agent with access to private data (files, email), exposure to untrusted content (web pages, API responses), and the ability to take consequential actions (send messages, write files) is exploitable. This is the [lethal trifecta](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/). shisad has all three by design — it's meant to be a useful assistant, not a sandboxed demo.

**The approach**: instead of removing capabilities until the agent is safe (at which point you've rebuilt ChatGPT with extra steps), shisad keeps all capabilities available and enforces safety per-call:

- **8-layer PEP pipeline** on every shared planner / `tool.execute` action: registry check, schema validation, capability check, DLP (secret pattern detection), resource authorization, egress allowlisting, credential host-scoping, taint sink enforcement
- **Taint tracking**: content firewalls tag untrusted input on ingress and enforce provenance-aware restrictions on egress — the runtime knows *who asked for* each action (user vs. injected content vs. model hallucination)
- **Confirmation gates**: user-requested actions proceed; actions with ambiguous or tainted provenance route to user confirmation with context; only genuine anomalies trigger lockdown
- **Approval surface parity**: routine channel-originated approvals stay on supported command surfaces with explicit approve/reject affordances or typed channel fallbacks; stronger method-specific proofs route truthfully to browser, helper, or external signer surfaces
- **Behavioral anomaly detection**: control plane consensus (5 independent voters) catches patterns that individual call-level checks miss
- **Destructive command protection**: under the supported containment profile,
  command policy is enforced before execution rather than by LLM judgment;
  unavailable required isolation fails closed. The separately selected
  `expert_host_fallback` posture does not carry that containment claim.

**Default posture**: built-in tools are not globally removed by a restrictive
policy, but configuration-dependent tools remain unavailable until their local
or external dependencies and credentials are configured. Operators who need a
more restrictive posture deploy an explicit policy via `SHISAD_POLICY_PATH`.

**Shared-path egress model**: allowlists auto-approve known-good destinations.
Explicit user requests proceed subject to the active policy. Destinations
suggested only by untrusted content route through confirmation with warning;
unattributed/hallucinated drift is blocked.

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
# Example: validate one affected module and its owning tests.
uv run ruff check src/shisad/core/host_matching.py tests/unit/test_host_matching.py
uv run mypy src/shisad/core/host_matching.py
uv run --python 3.12 pytest tests/unit/test_host_matching.py -q
```

Ordinary changes use targeted Python 3.12 validation. Full deterministic and
multi-version runs are checkpoint/release evidence, and contained suites are
not rerun separately. See `AGENTS.md` for the full validation cadence, coverage
rules, and commit conventions.

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
| `docs/memory-evals.md` | Memory evaluation commands, MELT report interpretation, and non-claims |
| `docs/memory-eval-sut-contract.md` | Versioned `shisad memory sut` protocol for external evaluators |
| `docs/adr/` | Architectural decision records |
| `docs/analysis/` | Security case studies and supply chain analysis |
| `docs/runbooks/` | Operator runbooks (browser setup, incident response, key rotation, rollback, skill revocation) |
| `runner/RUNBOOK.md` | Dev harness operator runbook |

- [agentic-security](https://github.com/lhl/agentic-security) — literature survey on LLM agent security (78 papers, defense taxonomy, production readiness assessment)
- [agentic-memory](https://github.com/lhl/agentic-memory) — literature survey on agent memory architectures and poisoning defenses (29+ references, attack taxonomy, defense recommendations)

## License

Apache License 2.0. See `LICENSE`.
