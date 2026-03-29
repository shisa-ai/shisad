# Environment Variables

This document is the operator-facing inventory of the repo's env-var surface.

Source of truth:

- `src/shisad/core/config.py`
- `src/shisad/core/providers/routing.py`
- `src/shisad/daemon/services.py`
- `src/shisad/memory/ingestion.py`

## Scope

There are three kinds of env vars in the current codebase:

1. `SHISAD_*`: daemon/runtime configuration
2. external provider credentials discovered by shisad (`OPENAI_API_KEY`, `SHISA_API_KEY`, etc.)
3. tool or CLI internal env vars (`_SHISAD_COMPLETE`, opt-in live-test vars, placeholders)

This surface is large. That is now documented, but it should be simplified in a future lane. A reasonable future direction is to move more operator settings into explicit config files and leave env vars for secrets and local overrides only. That is a future design decision, not part of this release.

## Parsing Rules

- Bool/int/float values use normal string parsing.
- List fields usually accept either CSV or JSON array syntax.
- Map/nested-object fields usually accept JSON object syntax.
- Path fields accept normal filesystem paths and `~`.
- Empty strings on optional fields are treated as unset in many route-local settings.

## Core `SHISAD_*` Daemon Settings

| Env var | Purpose |
|---|---|
| `SHISAD_DATA_DIR` | Root runtime data directory |
| `SHISAD_SOCKET_PATH` | Unix control socket path |
| `SHISAD_POLICY_PATH` | Trusted policy bundle path |
| `SHISAD_SELFMOD_ALLOWED_SIGNERS_PATH` | Trusted SSH `allowed_signers` file for self-mod artifacts |
| `SHISAD_LOG_LEVEL` | Daemon log level |
| `SHISAD_CHECKPOINT_TRIGGER` | Checkpoint creation strategy |
| `SHISAD_TRACE_ENABLED` | Enable trace recording |

## Channel and Identity Settings

Matrix:

- `SHISAD_MATRIX_ENABLED`
- `SHISAD_MATRIX_HOMESERVER`
- `SHISAD_MATRIX_USER_ID`
- `SHISAD_MATRIX_ACCESS_TOKEN`
- `SHISAD_MATRIX_ROOM_ID`
- `SHISAD_MATRIX_E2EE`
- `SHISAD_MATRIX_TRUSTED_USERS`
- `SHISAD_MATRIX_ROOM_WORKSPACE_MAP`

Discord:

- `SHISAD_DISCORD_ENABLED`
- `SHISAD_DISCORD_BOT_TOKEN`
- `SHISAD_DISCORD_DEFAULT_CHANNEL_ID`
- `SHISAD_DISCORD_TRUSTED_USERS`
- `SHISAD_DISCORD_GUILD_WORKSPACE_MAP`

Telegram:

- `SHISAD_TELEGRAM_ENABLED`
- `SHISAD_TELEGRAM_BOT_TOKEN`
- `SHISAD_TELEGRAM_DEFAULT_CHAT_ID`
- `SHISAD_TELEGRAM_TRUSTED_USERS`
- `SHISAD_TELEGRAM_CHAT_WORKSPACE_MAP`

Slack:

- `SHISAD_SLACK_ENABLED`
- `SHISAD_SLACK_BOT_TOKEN`
- `SHISAD_SLACK_APP_TOKEN`
- `SHISAD_SLACK_DEFAULT_CHANNEL_ID`
- `SHISAD_SLACK_TRUSTED_USERS`
- `SHISAD_SLACK_TEAM_WORKSPACE_MAP`

Identity gating:

- `SHISAD_CHANNEL_IDENTITY_ALLOWLIST`

## Assistant, Web, Filesystem, Reality Check, and Coding-Agent Settings

Assistant/persona:

- `SHISAD_ASSISTANT_PERSONA_TONE`
- `SHISAD_ASSISTANT_PERSONA_CUSTOM_TEXT`
- `SHISAD_CONTEXT_WINDOW`
- `SHISAD_SUMMARIZE_INTERVAL`
- `SHISAD_PLANNER_MEMORY_TOP_K`

Web:

- `SHISAD_WEB_SEARCH_ENABLED`
- `SHISAD_WEB_SEARCH_BACKEND_URL`
- `SHISAD_WEB_FETCH_ENABLED`
- `SHISAD_WEB_ALLOWED_DOMAINS`
- `SHISAD_WEB_TIMEOUT_SECONDS`
- `SHISAD_WEB_MAX_FETCH_BYTES`

Filesystem/git:

- `SHISAD_ASSISTANT_FS_ROOTS`
- `SHISAD_ASSISTANT_MAX_READ_BYTES`
- `SHISAD_ASSISTANT_GIT_TIMEOUT_SECONDS`

Reality Check:

- `SHISAD_REALITYCHECK_ENABLED`
- `SHISAD_REALITYCHECK_REPO_ROOT`
- `SHISAD_REALITYCHECK_DATA_ROOTS`
- `SHISAD_REALITYCHECK_ENDPOINT_ENABLED`
- `SHISAD_REALITYCHECK_ENDPOINT_URL`
- `SHISAD_REALITYCHECK_ALLOWED_DOMAINS`
- `SHISAD_REALITYCHECK_TIMEOUT_SECONDS`
- `SHISAD_REALITYCHECK_MAX_READ_BYTES`
- `SHISAD_REALITYCHECK_SEARCH_MAX_FILES`

Coding-agent:

- `SHISAD_CODING_REPO_ROOT`
- `SHISAD_CODING_AGENT_DEFAULT_PREFERENCE`
- `SHISAD_CODING_AGENT_DEFAULT_FALLBACKS`
- `SHISAD_CODING_AGENT_REGISTRY_OVERRIDES`
- `SHISAD_CODING_AGENT_TIMEOUT_SECONDS`

## `SHISAD_SECURITY_*`

| Env var | Purpose |
|---|---|
| `SHISAD_SECURITY_DEFAULT_DENY` | Legacy compatibility knob; runtime default comes from policy |
| `SHISAD_SECURITY_REQUIRE_CONFIRMATION_FOR_WRITES` | Write/send confirmation default |
| `SHISAD_SECURITY_EGRESS_DEFAULT_DENY` | Global egress default |
| `SHISAD_SECURITY_CREDENTIAL_STORE_PATH` | Encrypted credential store path |
| `SHISAD_SECURITY_AUDIT_LOG_PATH` | Audit log override |

## `SHISAD_MODEL_*`

Global route settings:

- `SHISAD_MODEL_BASE_URL`
- `SHISAD_MODEL_MODEL_ID`
- `SHISAD_MODEL_PLANNER_MODEL_ID`
- `SHISAD_MODEL_EMBEDDINGS_MODEL_ID`
- `SHISAD_MODEL_MONITOR_MODEL_ID`
- `SHISAD_MODEL_PINNED_MONITOR_MODEL_ID`
- `SHISAD_MODEL_PINNED_PLANNER_MODEL_ID`
- `SHISAD_MODEL_ENFORCE_SECURITY_ROUTE_PINNING`
- `SHISAD_MODEL_API_KEY`
- `SHISAD_MODEL_REMOTE_ENABLED`
- `SHISAD_MODEL_ALLOW_HTTP_LOCALHOST`
- `SHISAD_MODEL_BLOCK_PRIVATE_RANGES`
- `SHISAD_MODEL_ENDPOINT_ALLOWLIST`
- `SHISAD_MODEL_LOG_PROMPTS`

Planner route:

- `SHISAD_MODEL_PLANNER_PROVIDER_PRESET`
- `SHISAD_MODEL_PLANNER_BASE_URL`
- `SHISAD_MODEL_PLANNER_REMOTE_ENABLED`
- `SHISAD_MODEL_PLANNER_API_KEY`
- `SHISAD_MODEL_PLANNER_AUTH_MODE`
- `SHISAD_MODEL_PLANNER_AUTH_HEADER_NAME`
- `SHISAD_MODEL_PLANNER_EXTRA_HEADERS`
- `SHISAD_MODEL_PLANNER_ENDPOINT_FAMILY`
- `SHISAD_MODEL_PLANNER_REQUEST_PARAMETER_PROFILE`
- `SHISAD_MODEL_PLANNER_CAPABILITIES`
- `SHISAD_MODEL_PLANNER_SCHEMA_STRICT_MODE`
- `SHISAD_MODEL_PLANNER_REQUEST_PARAMETERS`

Embeddings route:

- `SHISAD_MODEL_EMBEDDINGS_PROVIDER_PRESET`
- `SHISAD_MODEL_EMBEDDINGS_BASE_URL`
- `SHISAD_MODEL_EMBEDDINGS_REMOTE_ENABLED`
- `SHISAD_MODEL_EMBEDDINGS_API_KEY`
- `SHISAD_MODEL_EMBEDDINGS_AUTH_MODE`
- `SHISAD_MODEL_EMBEDDINGS_AUTH_HEADER_NAME`
- `SHISAD_MODEL_EMBEDDINGS_EXTRA_HEADERS`
- `SHISAD_MODEL_EMBEDDINGS_ENDPOINT_FAMILY`
- `SHISAD_MODEL_EMBEDDINGS_REQUEST_PARAMETER_PROFILE`
- `SHISAD_MODEL_EMBEDDINGS_CAPABILITIES`
- `SHISAD_MODEL_EMBEDDINGS_REQUEST_PARAMETERS`

Monitor route:

- `SHISAD_MODEL_MONITOR_PROVIDER_PRESET`
- `SHISAD_MODEL_MONITOR_BASE_URL`
- `SHISAD_MODEL_MONITOR_REMOTE_ENABLED`
- `SHISAD_MODEL_MONITOR_API_KEY`
- `SHISAD_MODEL_MONITOR_AUTH_MODE`
- `SHISAD_MODEL_MONITOR_AUTH_HEADER_NAME`
- `SHISAD_MODEL_MONITOR_EXTRA_HEADERS`
- `SHISAD_MODEL_MONITOR_ENDPOINT_FAMILY`
- `SHISAD_MODEL_MONITOR_REQUEST_PARAMETER_PROFILE`
- `SHISAD_MODEL_MONITOR_CAPABILITIES`
- `SHISAD_MODEL_MONITOR_REQUEST_PARAMETERS`

Notes:

- `*_EXTRA_HEADERS`, `*_CAPABILITIES`, and `*_REQUEST_PARAMETERS` are JSON-object fields.
- Route-local `*_REMOTE_ENABLED` fields accept empty/unset to mean “inherit global”.
- `SHISAD_MODEL_API_KEY` is the generic global override, but preset-native key envs are also recognized.

## Direct Env Reads Outside `BaseSettings`

These are still part of the live surface:

| Env var | Purpose |
|---|---|
| `SHISAD_MEMORY_MASTER_KEY` | Optional memory-encryption secret override |
| `OPENAI_API_KEY` | OpenAI preset credential discovery |
| `SHISA_API_KEY` | SHISA preset credential discovery |
| `OPENROUTER_API_KEY` | OpenRouter preset credential discovery |
| `GEMINI_API_KEY` | Google OpenAI-compatible preset credential discovery |
| `_SHISAD_COMPLETE` | shell-completion internal env, not operator config |

## Opt-In Test / Dev Knobs

These are repo/test helpers, not normal operator runtime config:

| Env var | Purpose |
|---|---|
| `SHISAD_LIVE_MODEL_TESTS` | opt-in live-model behavioral suite |
| `SHISAD_LIVE_CODING_AGENTS` | opt-in live coding-agent smoke suite |

## Dev Harness Minimum Useful Subset

For local dev work, the runner harness (`runner/harness.sh`) sets sane defaults
automatically. If configuring manually, the core subset is:

```bash
export SHISAD_DATA_DIR="$PWD/.local/shisad-dev"
export SHISAD_SOCKET_PATH="/tmp/shisad-dev.sock"
export SHISAD_POLICY_PATH="$PWD/.local/policy.yaml"
export SHISAD_CODING_REPO_ROOT="$PWD"
export SHISAD_CODING_AGENT_DEFAULT_PREFERENCE='["codex","claude"]'
export SHISAD_CODING_AGENT_DEFAULT_FALLBACKS='["claude"]'
export SHISAD_CODING_AGENT_TIMEOUT_SECONDS=1800
export SHISAD_MODEL_PLANNER_PROVIDER_PRESET="shisa_default"
export SHISAD_MODEL_PLANNER_REMOTE_ENABLED=true
export SHISA_API_KEY="..."
```

See `runner/RUNBOOK.md` for the full bootstrap flow.
