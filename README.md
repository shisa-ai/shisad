# ShisaD (`shisad`)

[Security-first](docs/SECURITY.md) AI agent daemon framework.

ShisaD is a long-running daemon that connects an LLM to tools, files, networks,
and messaging channels. The model proposes actions; ShisaD checks each action
against policy, considers where the request came from, asks for confirmation
when required, and records the decision. Local administrative commands use
separate validation and logging rules, documented in the
[administrative route reference](docs/AUTHORITY-MAP.md).

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

- **Long-term memory** — ShisaD stores identity, current priorities, recalled
  facts, procedures, and supporting evidence separately in versioned local
  storage. Each entry records where it came from, and higher-risk additions
  require review
- **Isolated delegated work** — ShisaD keeps the main conversation active in a
  COMMAND session while handing delegated work—including work with untrusted,
  or tainted, content—to separate TASK sessions. Raw TASK output cannot enter
  COMMAND directly; it must pass through a summary firewall that returns a
  sanitized, structured summary. This separation helps prevent untrusted
  instructions from persisting in the long-lived COMMAND context. Each task
  also records its assigned scope and keeps approvals linked to the request
  that authorized them
- **Every action is checked before execution** — each action proposed by the
  planner or submitted through `tool.execute` passes through the Policy
  Enforcement Point (PEP), rather than being checked only when the session
  starts. It validates the tool and its arguments, checks permissions and
  resource access, restricts network destinations and credential use, scans
  for secrets, and applies additional rules when untrusted data reaches a
  sensitive destination
- **Ingress and egress content controls** — on ingress, ShisaD's content
  firewall scans untrusted input, marks it as tainted, and records where it
  came from. The system preserves those labels while content is processed and
  when it is stored. On egress, the output firewall checks content before it
  leaves, while policy uses the labels to determine whether related actions can
  proceed, require confirmation, or be blocked
- **Confirmation gates, not blanket denial** — user-requested actions proceed; ambiguous or tainted actions route to confirmation; only genuine anomalies trigger lockdown
- **Approve actions where they were requested** — on supported interfaces,
  users can approve or reject a pending action in the same conversation where
  it originated. The `shisad` CLI remains available as a fallback
- **Detect suspicious behavior across actions** — ShisaD combines signals from
  five independent monitors to detect patterns that a single action check
  might miss. It can warn the user, limit repeated requests, or enter lockdown
  when multiple signals indicate a genuine anomaly
- **Destructive command protection** — ShisaD checks shell commands before
  execution and blocks known destructive patterns independently of the model.
  In the standard supported
  configuration, commands run only when the required isolation is available.
  Operators can explicitly select `expert_host_fallback` to run commands
  without supported isolation, and ShisaD reports that weaker state
- **Clean-room administrative changes** — ShisaD handles changes to policy,
  configuration, credentials, and capabilities in a fresh SUDO session
  containing only the current authenticated request and trusted system state.
  It produces a proposal for review instead of applying changes automatically
- **Messaging channels** — receive and send messages through Matrix, Discord,
  Telegram, and Slack Socket Mode. By default, only user IDs explicitly allowed
  for each channel can interact with the daemon
- **Built-in assistant tools** — take notes, manage todos, schedule tasks,
  deliver results through configured channels, search and fetch web content,
  automate browser tasks, work with files and Git repositories, and refer to
  large untrusted results without loading them into the conversation history
- **Keep large untrusted content out of conversation history** — web pages,
  email bodies, and large tool results are stored separately and represented by
  stable references that survive daemon restarts. Raw content is loaded into an
  isolated, single-turn context only when needed, and terminal output is
  escaped to prevent control-sequence attacks
- **Actions must match the user's intent** — before a risky action runs,
  ShisaD verifies that it follows the user's intent, either directly from their
  request or from a plan created in a clean COMMAND session. A read involving a
  path that does not exist requires confirmation, while an action that would
  create or change an unverified missing path is blocked
- **Flexible model routing** — configure Shisa, OpenAI, OpenRouter, Google, and
  local vLLM providers with separate credentials and model choices. A single
  deployment can use different routes for different workloads and combine
  local and remote models
- **Detect unexpected tool changes** — reviewed local skills can add tools, and
  ShisaD records a fingerprint of each skill bundle and declared tool. If
  either changes unexpectedly, the affected skill is not loaded and the
  discrepancy is recorded in the audit log. Tools discovered through remote
  Model Context Protocol (MCP) servers are treated as untrusted and require
  confirmation unless the server is explicitly trusted
- **Observability** — comprehensive audit trail, TUI dashboard (pending actions, tasks, channel health, alerts), and `doctor` diagnostics

## Status

ShisaD is public and under heavy development. The latest published release is
`v0.8.2.1`.

| Version | Focus |
|---------|-------|
| v0.8.2 | Guided onboarding, reliable startup, session-scoped chat and Discord progress, data recovery, audit verification, and channel administration |
| v0.8.1 | Installation and configuration improvements, restart-safe action tracking, safer filesystem and process boundaries, and restart recovery for delivery and approvals across four messaging channels |
| v0.8.0 | Command-channel approvals, TUI/confirmation polish, task panels, and stable UX-overhaul foundation |
| v0.8 beta | Bug-fix checkpoint before the stable UX overhaul (latest beta: `v0.8.0b1`) |
| v0.7 | Memory foundation + long-term memory/evaluation surfaces (latest published: `v0.7.4`) |
| v0.6 | COMMAND/TASK orchestration, credential controls, web tools, and initial browser automation |
| v0.5 | First public release — evidence references, repo split, zero-config SHISA provider |
| v0.4 | Self-modification, coding-agent runtime, COMMAND/TASK isolation |
| v0.3 | Provider routing, channels, assistant tools, destructive command protection |
| v0.2 | Structural refactor (typed handlers, decomposed runtime, coverage) |
| v0.1 | Core daemon, PEP security pipeline, control API |

This table tracks major release lines for reader orientation; patch releases
like `v0.5.1` and `v0.5.2` stay in the changelog rather than being listed here.

See [`docs/ROADMAP.md`](docs/ROADMAP.md) for current direction and
[`CHANGELOG.md`](CHANGELOG.md) for shipped release history.

## Getting Started

> ShisaD is under heavy development and currently intended for developers. The
> easiest installation path is to ask Claude Code, OpenAI Codex, or another
> capable coding agent to follow the deployment guide.

For complete installation and deployment instructions—including preparing the
host, configuring a model provider, connecting messaging channels, and
troubleshooting—see [`docs/DEPLOY.md`](docs/DEPLOY.md). Run ShisaD on a
dedicated instance or container rather than inside your development
environment.

### Quick Start

For a normal `v0.8.2.1` installation, install the `assistant` package extra:

```bash
uv tool install 'shisad[assistant]'
shisad --help
shisad doctor check --component all
```

Run `shisad` with no arguments for a read-only readiness check, then use
`shisad setup wizard` for guided interactive setup. Automated deployments can
use `shisad setup apply --selection FILE`; it writes only when `--write` is
provided. See [`docs/DEPLOY.md`](docs/DEPLOY.md) for the complete setup flow.

The `assistant` extra installs the terminal interface and client libraries for
MCP, Matrix end-to-end encryption (E2EE), Discord, Telegram, and Slack. It does
not enable channels or add credentials; configure those explicitly.
PromptGuard remains optional, so install `shisad[assistant,promptguard]` only
if you want its local model-based checks.

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

For package installs, use the first-class PromptGuard extra, for example
`uv pip install 'shisad[promptguard]'`. `security-runtime` is a uv dependency
group, not a pip extra; use `--group security-runtime`, not
`--extra security-runtime`. The `assistant`, `chat`, and `promptguard` package
sets are project optional extras; `assistant` is the complete consumer profile,
while `chat` remains the smaller Textual-only profile.

Memory retrieval prefers Python's `sqlite3` runtime to have SQLite FTS5
enabled. ShisaD falls back when FTS5 is unavailable, but you should verify the
preferred path with `uv run shisad doctor check --component storage`; see
[`docs/runbooks/SQLITE.md`](docs/runbooks/SQLITE.md) for install guidance.

### Configuration

Environment variables use `SHISAD_` prefixes. Full reference: `docs/ENV-VARS.md`.

The v0.8.2.1 CLI can create and inspect configuration without starting the
daemon:

```bash
shisad
shisad init --non-interactive
shisad config validate
shisad config upgrade
shisad config show --format human
shisad config diff --format human
shisad config schema --format json
shisad env --format human
```

`shisad init` creates one owner-only commented template at
`$XDG_CONFIG_HOME/shisad/config.toml` (normally
`~/.config/shisad/config.toml`) and refuses an existing or symlink destination.
It is deliberately not a setup wizard: it does not copy ambient secrets,
configure a provider or policy, create daemon state, or start the daemon. Use
the global `--config FILE` option to select another path. ShisaD resolves
settings in this order, from highest to lowest priority: command-line options,
environment variables, TOML configuration, and built-in defaults.
Configuration display, comparison, environment, and validation output redact
fields that may contain secrets.

Guided setup is available through `shisad setup wizard`. It displays the
selected provider, policy, and channels before writing configuration. After
setup, use `shisad start`, `shisad status`, and `shisad tour`; containers and
service supervisors should use `shisad start --foreground`.

Chat, the one-shot terminal dashboard, and the static web snapshot share the
three built-in palettes `shisa-dark`, `shisa-light`, and
`shisa-high-contrast`. Select one with `SHISAD_UI_THEME`, disable optional
motion with `SHISAD_REDUCE_MOTION=true`, and suppress palette color with
`NO_COLOR` or a root flag such as `shisad --no-color tui`. Custom theme files
are not supported. `shisad web-ui` creates a static local snapshot for
investigation or export; it is not a live web application. The snapshot can
contain session data, pending actions, alerts, and network-review details, so
keep it private and remove it when the investigation is complete.

The `shisad` CLI returns exit status 0 for success, 1 for command or user-state
errors, 2 for daemon connection or command-line usage errors, and 3 for invalid
or unsafe configuration. `shisad doctor` is read-only and has no automatic
repair mode. Help uses the `reality-check` spelling; the older `realitycheck`
spelling remains available as a hidden compatibility alias.

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

ShisaD assumes prompt injection will succeed and builds enforcement outside the
model. On the shared planner path, the LLM is a planner, not an executor: it
proposes tool calls, while runtime enforcement decides whether each call
proceeds, requires confirmation, or is blocked. Those enforcement decisions do
not come from the model. Authenticated local operator convenience RPCs do not
claim the same PEP/control-plane path; their exact route-local boundaries are
listed in [`docs/AUTHORITY-MAP.md`](docs/AUTHORITY-MAP.md).

**The problem**: any agent with access to private data (files, email), exposure to untrusted content (web pages, API responses), and the ability to take consequential actions (send messages, write files) is exploitable. This is the [lethal trifecta](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/). ShisaD has all three by design — it's meant to be a useful assistant, not a sandboxed demo.

**The approach**: instead of removing capabilities until the agent is safe (at which point you've rebuilt ChatGPT with extra steps), ShisaD keeps all capabilities available and enforces safety per-call:

- **Eight checks before execution** — every action from the shared planner or
  `tool.execute` is checked for tool registration, valid arguments,
  permissions, exposed secrets, resource access, approved destinations,
  credential scope, and restrictions on tainted content
- **Track untrusted content** — ingress controls label untrusted content as
  tainted and record its source. Those labels remain attached while the content
  is processed and stored, and egress controls use that provenance to
  distinguish actions arising from the user's intent, untrusted content, or
  unsupported model output
- **Require confirmation when provenance is unclear** — actions matching the
  user's intent can proceed when policy allows. Actions arising from ambiguous
  or tainted content require confirmation with context. Lockdown is reserved
  for behavior that the anomaly monitors identify as a threat
- **Approvals stay where users can complete them** — routine approvals remain
  in the supported interface where the request originated, using Approve/Reject
  controls or clear fallback instructions. When an approval requires stronger
  proof, ShisaD directs the user to the appropriate browser, local helper, or
  external signing device instead of claiming the current interface can
  complete it
- **Behavioral anomaly detection** — five independent monitors combine their
  signals to identify suspicious behavior that a single action check might miss
- **Destructive command protection** — under the supported containment profile,
  ShisaD checks commands against policy before execution; the model does not
  make this decision. A command does not run if required isolation is
  unavailable. Operators can explicitly choose `expert_host_fallback` to run
  without supported isolation, but that mode does not provide the same
  containment

**Security controls preserve tool access** — ShisaD's default policy keeps every
built-in tool available and applies the required confirmation, isolation,
credential, and audit checks when it runs. Tools that depend on external
services, local software, or credentials become usable once those requirements
are configured. Operators can define additional limits through a policy file
selected with `SHISAD_POLICY_PATH`.

**Egress controls** — known destinations can be approved in advance. A
destination explicitly requested by the user can proceed when policy allows
it. A destination suggested only by untrusted content requires confirmation,
while one with no connection to the user's intent is blocked.

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
not rerun separately. See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the validation cadence, coverage
rules, and commit conventions.

## Documentation

| Doc | Description |
|-----|-------------|
| `CONTRIBUTING.md` | Human contributor guide, validation, and documentation boundaries |
| `docs/DESIGN-PHILOSOPHY.md` | First-principles reference — read this first |
| `docs/DEPLOY.md` | Public bring-up and deployment quickstart |
| `docs/SECURITY.md` | Security architecture — threat model, enforcement layers, trust boundaries |
| `docs/ROADMAP.md` | Public product roadmap and release direction |
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
