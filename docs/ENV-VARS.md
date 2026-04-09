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
| `SHISAD_REQUIRE_LOCAL_ADAPTERS` | Require pre-installed coding-agent binaries; disallow runtime `npx` fetches (`1`/`true`/`yes`) |

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

Web notes:

- `SHISAD_WEB_SEARCH_BACKEND_URL` must point at a compatible search backend that serves JSON search results over HTTP(S). The current runtime expects a SearxNG-style `/search` endpoint.
- The search backend host must also be present in `SHISAD_WEB_ALLOWED_DOMAINS`, alongside any fetch/search destinations you want auto-approved in the tested environment.
- If `SHISAD_WEB_SEARCH_BACKEND_URL` is unset, `tool.web.search` stays available in the registry but reports `web_search_backend_unconfigured` in live tool-status checks instead of silently locking down the session.

Browser:

- `SHISAD_BROWSER_ENABLED`
- `SHISAD_BROWSER_COMMAND`
- `SHISAD_BROWSER_ALLOWED_DOMAINS`
- `SHISAD_BROWSER_TIMEOUT_SECONDS`
- `SHISAD_BROWSER_REQUIRE_HARDENED_ISOLATION`
- `SHISAD_BROWSER_MAX_READ_BYTES`

Browser notes:

- `SHISAD_BROWSER_ENABLED=1` turns on the planner-visible browser tool surface (`browser.navigate`, `browser.read_page`, `browser.screenshot`, `browser.click`, `browser.type_text`, `browser.end_session`).
- `SHISAD_BROWSER_COMMAND` must point at a Playwright-compatible browser CLI. In tests and local harness runs this can be a wrapper script; in operator environments it is typically a real Playwright CLI install.
- If `SHISAD_BROWSER_ALLOWED_DOMAINS` is empty, both the runtime browser sandbox policy and the planner/PEP browser tool registry fall back to `SHISAD_WEB_ALLOWED_DOMAINS`.
- `SHISAD_BROWSER_ALLOWED_DOMAINS` acts as an auto-approve/browser-egress scope seed, not a hard deny wall for explicit public-host navigation; the runtime still adds the concrete requested browser host to the per-action sandbox allowlist.
- Hardened browser isolation currently requires literal browser scope entries. If `SHISAD_BROWSER_REQUIRE_HARDENED_ISOLATION=1`, wildcard host patterns in `SHISAD_BROWSER_ALLOWED_DOMAINS` or the `SHISAD_WEB_ALLOWED_DOMAINS` fallback are rejected fail-closed because the connect-path runtime cannot precompute wildcard sibling hosts safely.
- Read-mostly browser actions (`browser.navigate`, `browser.read_page`, `browser.screenshot`, `browser.end_session`) are intended to proceed without confirmation when the destination is authorized. Browser write actions (`browser.click`, `browser.type_text`) are confirmation-gated.
- Loopback/private browser targets remain blocked by the sandbox unless the target host is explicitly allowlisted for the browser surface in the current configuration.
- `SHISAD_BROWSER_REQUIRE_HARDENED_ISOLATION` defaults to `1`. Keep it enabled unless you are deliberately running a non-production browser integration and understand that disabling it weakens the browser isolation boundary.

Approval / WebAuthn / signer:

- `SHISAD_APPROVAL_ORIGIN`
- `SHISAD_APPROVAL_RP_ID`
- `SHISAD_APPROVAL_BIND_HOST`
- `SHISAD_APPROVAL_BIND_PORT`
- `SHISAD_APPROVAL_LINK_TTL_SECONDS`
- `SHISAD_APPROVAL_RATE_LIMIT_WINDOW_SECONDS`
- `SHISAD_APPROVAL_RATE_LIMIT_MAX_ATTEMPTS`
- `SHISAD_SIGNER_KMS_URL`
- `SHISAD_SIGNER_KMS_BEARER_TOKEN`
- `SHISAD_EVIDENCE_KMS_URL`
- `SHISAD_EVIDENCE_KMS_BEARER_TOKEN`
- `SHISAD_EVIDENCE_KMS_TIMEOUT_SECONDS`

Approval notes:

- `SHISAD_APPROVAL_ORIGIN` enables the daemon-owned browser ceremony surface used for passkey registration and `bound_approval` action confirmation.
- `SHISAD_APPROVAL_ORIGIN` must be a full origin only (`scheme://host[:port]` with no path/query/fragment). Non-loopback origins must use `https`; loopback `http` is allowed only for local development and tests.
- `SHISAD_APPROVAL_ORIGIN` is canonicalized to the browser/WebAuthn effective origin: explicit default ports (`:80` on `http`, `:443` on `https`) are normalized away, and IPv6 loopback origins keep bracketed host formatting.
- During WebAuthn verification, the signed browser origin must still resolve to that same effective origin. The runtime accepts the exact canonical origin plus root-equivalent forms with an explicit default port and/or a lone trailing `/`, but rejects userinfo, non-root paths, query strings, and fragments fail-closed.
- `SHISAD_APPROVAL_RP_ID` defaults to the approval-origin hostname when unset.
- `SHISAD_APPROVAL_BIND_HOST` and `SHISAD_APPROVAL_BIND_PORT` control the local listener that serves the ceremony pages. They can differ from the public approval origin when a reverse proxy or tailnet HTTPS endpoint fronts the daemon.
- `SHISAD_APPROVAL_LINK_TTL_SECONDS` sets the expiry for registration and approval links. POST attempts against those links are rate-limited by `SHISAD_APPROVAL_RATE_LIMIT_WINDOW_SECONDS` and `SHISAD_APPROVAL_RATE_LIMIT_MAX_ATTEMPTS`.
- WebAuthn `bound_approval` requires user-verifying authenticators (PIN/biometric/passkey UX). Sign-count rollback detection is best-effort only; authenticators that always report `counter=0` do not provide clone-detection signal.
- If `SHISAD_APPROVAL_ORIGIN` is unset, the browser/WebAuthn ceremony surface stays unavailable, but SSH/private deployments can still use `shisad-approver` with the daemon's `local_fido2` helper path for L2 `bound_approval`. The baseline `software` / `totp` confirmation flows remain available regardless.
- `SHISAD_SIGNER_KMS_URL` enables the enterprise-style HTTPS signer backend used for `signed_authorization` approvals. When unset, the `kms` signer method stays unavailable and signer-backed policies fail closed with actionable errors.
- `SHISAD_SIGNER_KMS_BEARER_TOKEN`, when set, is sent as an `Authorization: Bearer ...` header to that signer endpoint.
- The `kms` endpoint contract is:
  Request body:
  ```json
  {
    "schema_version": "shisad.sign_request.v1",
    "backend": "kms",
    "signer_key_id": "kms:finance-primary",
    "intent_envelope_hash": "sha256:...",
    "intent_envelope": { "...": "shisad.intent.v1 payload" },
    "timeout_seconds": 300
  }
  ```
  Response body:
  ```json
  {
    "status": "approved|rejected|expired|error",
    "signer_key_id": "kms:finance-primary",
    "signature": "base64:...",
    "signed_at": "2026-04-08T12:00:00Z",
    "review_surface": "provider_ui|opaque_device|trusted_device_display",
    "blind_sign_detected": false,
    "reason": ""
  }
  ```
- `status`, `signed_at`, and `blind_sign_detected` are validated fail-closed; malformed values return `signer_backend_invalid_response`.
- The daemon verifies the returned signature against the locally registered public key for `signer_key_id`; the KMS response can deny service or downgrade review quality, but it cannot mint approvals without a valid local signature check.
- For the current `kms` backend, backend-reported review surfaces are clamped to the daemon's configured trust ceiling. In practice this means `opaque_device` can downgrade the approval, but `trusted_device_display` does not upgrade the enterprise HTTPS backend beyond `signed_authorization`.
- Registered signer public keys still live in the same daemon-owned approval-factor store as TOTP/WebAuthn/helper factors. `L1` encrypts ArtifactLedger blob payloads only; approval-factor and recovery-code at-rest hardening remains follow-on.

Evidence-at-rest notes:

- `SHISAD_EVIDENCE_KMS_URL` enables the remote artifact-crypt boundary used for ArtifactLedger blob payloads. When unset, the shipped default remains plaintext ArtifactLedger blob storage on the daemon filesystem.
- `SHISAD_EVIDENCE_KMS_BEARER_TOKEN`, when set, is sent as an `Authorization: Bearer ...` header to that artifact-crypt endpoint.
- `SHISAD_EVIDENCE_KMS_TIMEOUT_SECONDS` sets the per-request timeout for ArtifactLedger encrypt/decrypt RPCs.
- Scope is intentionally narrow and truth-scoped: only blob payload bytes are encrypted. Artifact metadata remains plaintext in `refs_index.json` so ref lifecycle, deduplication, and GC still work. That plaintext metadata includes `ref_id`, `content_hash`, `summary`, `source`, timestamps, taint labels, endorsement state, and storage codec.
- The artifact-crypt endpoint contract is:
  Request body:
  ```json
  {
    "schema_version": "shisad.artifact_crypt.v1",
    "operation": "encrypt|decrypt",
    "artifact_kind": "evidence",
    "payload_b64": "<base64-encoded bytes>"
  }
  ```
  Response body:
  ```json
  {
    "status": "ok",
    "payload_b64": "<base64-encoded bytes>"
  }
  ```
- Non-`ok` responses, malformed JSON, invalid base64, or invalid UTF-8 plaintext fail closed. New writes degrade to an `[EVIDENCE unavailable ...]` stub for that turn instead of silently downgrading the storage claim.
- Decrypt failures from the remote artifact-crypt boundary do not delete the ref automatically; the daemon preserves the metadata row so the evidence can recover later if the correct key boundary comes back. Proven local corruption cases such as missing blobs, codec mismatch, or content-hash mismatch still invalidate and drop the ref.

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
| `SHISAD_SECURITY_CREDENTIAL_STORE_PATH` | Encrypted egress credential store path |
| `SHISAD_SECURITY_APPROVAL_FACTOR_STORE_PATH` | Approval-factor and signer-key state path (daemon-owned JSON until at-rest encryption lands) |
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
