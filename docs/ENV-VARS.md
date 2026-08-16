# Environment Variables

This document is the user-facing inventory of the repo's env-var surface.

Source of truth:

- `src/shisad/core/config.py`
- `src/shisad/core/config_file.py`
- `src/shisad/core/providers/routing.py`
- `src/shisad/daemon/services.py`
- `src/shisad/interop/a2a_registry.py`
- `src/shisad/memory/ingestion.py`
- `src/shisad/core/process_environment.py`

Inventory checked against `shisad env --format json` at public development ref
`d4d2f465` on 2026-07-22. Direct provider/test reads are listed separately
below because they are not all ordinary operator settings.

## Scope

There are three kinds of env vars in the current codebase:

1. `SHISAD_*`: daemon/runtime configuration
2. external provider credentials discovered by shisad (`OPENAI_API_KEY`, `SHISA_API_KEY`, etc.)
3. tool or CLI internal env vars (`_SHISAD_COMPLETE`, opt-in live-test vars, placeholders)

The same typed settings are available in an operator-authored TOML file. Use
`shisad init --non-interactive` for one no-overwrite owner-only commented template,
`shisad config template` to print that template without writing it, and
`shisad config validate|show|schema|diff` plus `shisad env` for human or JSON
inspection. Effective values and sources are derived from the same typed loader
and secret-bearing fields are redacted.

## Artifact Profiles

The `v0.8.1` release's consumer package profile is `shisad[assistant]`. It
installs runtime libraries but does not set any `SHISAD_*` channel flag,
endpoint, or credential. PromptGuard remains the separate `promptguard` extra.

The local Linux container candidate supplies these non-secret defaults:

- `HOME=/home/shisad`
- `XDG_RUNTIME_DIR=/run/shisad`
- `SHISAD_DATA_DIR=/var/lib/shisad`
- `SHISAD_SOCKET_PATH=/run/shisad/control.sock`
- `SHISAD_ASSISTANT_FS_ROOTS=["/workspace"]`

Pass provider/channel settings at `docker run` time with an operator-owned env
file or secret mechanism; do not add them to the Dockerfile or build context.
The daemon runs as uid/gid `10001`, so bind-mounted paths must grant that
identity only the access intended. The image does not silently alter
`SHISAD_POLICY_PATH` or select `expert_host_fallback`; mount an operator policy
at `/etc/shisad/policy.yaml` and verify the effective sandbox posture with
`shisad doctor check --component sandbox`.

## TOML Configuration and Precedence

Pass `--config /path/to/config.toml`, set `SHISAD_CONFIG_PATH`, or place the
file at `$XDG_CONFIG_HOME/shisad/config.toml` (default
`~/.config/shisad/config.toml`). An explicitly selected missing file is an
error; an absent default file uses typed defaults without creating files.

The file uses `schema_version = 1` and `[daemon]`, `[model]`, and `[security]`
tables. Field names are the lowercase names shown by `shisad config template`.
Precedence is command-line override, then environment, then TOML, then default.
Parsing is read-only and does not create the configured data directory.

There is intentionally no `init --from-env` migration command in this release.
`init --non-interactive` names the same minimal no-prompt behavior; it does not
copy environment values. Use the generated template and `config show` rather
than assuming environment values were written to disk.

`shisad init` writes only the generated comments/default examples. It refuses
existing files, symlink destinations, and destinations inside configured data
or assistant-managed roots; it does not configure providers or policy, create
daemon state, or start the daemon. `config validate`, `config show`, `config
schema`, `config diff`, and `shisad env` are read-only. Each accepts `--format
human|json`; `config show` retains JSON as its compatibility default.

`shisad setup apply --selection FILE` is the deterministic managed/automation
path for final provider, policy, and channel setup. It never prompts and is a
dry run unless `--write` is present. The selection document may contain logical
credential references but no raw-secret field. Final TOML uncomments only the
validated selected fields and never copies ambient provider/channel secrets.
The sibling policy and config files are each created exclusively at `0600`;
they are ordered policy then config but are not a cross-file transaction.

## Child-Process Environment Boundaries

Shisad-owned subprocesses do not all receive the daemon's full environment.
Each launch family uses a typed profile containing only its process basics and
operation-scoped inputs. In particular:

- the control-plane sidecar retains `SHISAD_MODEL_*`, supported model-provider
  API keys, proxy/TLS settings, and `SHISAD_LOG_LEVEL`, but not unrelated
  channel or signer credentials;
- coding-agent ACP children retain supported provider auth and transport
  settings, while ambient Python/Node injection controls and Git helper
  controls are excluded;
- msgvault and MCP stdio children retain their bounded runtime context. An MCP
  server's explicit `env` mapping is applied only to that server after ambient
  filtering; shell-function exports remain excluded;
- shisad-owned Git worktree and evaluation commands execute in a fixed
  non-interactive environment rather than ambient global/system Git config or
  askpass, pager, and helper controls. A bounded read-only preflight can locate
  normal system/global config files solely to classify a repository-selected
  checkout filter; ambient `GIT_CONFIG_*` overrides do not steer that preflight,
  and configured helper values are never executed by it.

These profiles bound inheritance; they are not a general host-process sandbox.
Configured child programs still receive their explicit arguments and any
component-scoped credentials documented above.

## Parsing Rules

- Bool/int/float values use normal string parsing.
- List fields usually accept either CSV or JSON array syntax.
- For env files that are loaded with shell `source` / `.`, prefer CSV for list
  fields because it avoids shell quoting pitfalls. If you use JSON-array syntax
  in a shell-sourced file, quote the whole value, for example
  `SHISAD_WEB_ALLOWED_DOMAINS='["a.com","b.com"]'`. Unquoted JSON arrays such
  as `SHISAD_WEB_ALLOWED_DOMAINS=["a.com","b.com"]` lose their inner quotes
  during shell parsing and arrive as invalid JSON (`[a.com,b.com]`).
- Map/nested-object fields usually accept JSON object syntax.
- Path fields accept normal filesystem paths and `~`.
- Empty strings on optional fields are treated as unset in many route-local settings.

## Core `SHISAD_*` Daemon Settings

| Env var | Purpose |
|---|---|
| `SHISAD_DATA_DIR` | Root runtime data directory |
| `SHISAD_SOCKET_PATH` | Unix control socket path; defaults to `$XDG_RUNTIME_DIR/shisad/control.sock` when `XDG_RUNTIME_DIR` is an absolute path, otherwise `/tmp/shisad-<uid>/control.sock` |
| `SHISAD_POLICY_PATH` | Trusted policy bundle path |
| `SHISAD_CONFIG_PATH` | Explicit operator TOML path; equivalent to root `--config` at lower precedence |
| `SHISAD_SELFMOD_ALLOWED_SIGNERS_PATH` | Trusted SSH `allowed_signers` file for self-mod artifacts |
| `SHISAD_LOG_LEVEL` | Daemon log level |
| `SHISAD_CONTROL_PLANE_STARTUP_TIMEOUT_SECONDS` | Readiness timeout for the isolated control-plane sidecar; minimum `0.1`, default `15.0` seconds |
| `SHISAD_CHANNEL_STARTUP_TIMEOUT_SECONDS` | Per-channel startup and failed-start cleanup timeout; minimum `0.1`, default `15.0` seconds. A timed-out optional channel is excluded from active routing while the core daemon continues when cleanup succeeds |
| `SHISAD_CHECKPOINT_TRIGGER` | Checkpoint creation strategy |
| `SHISAD_UI_THEME` | Built-in renderer palette: `shisa-dark`, `shisa-light`, or `shisa-high-contrast` |
| `SHISAD_REDUCE_MOTION` | Disable optional UI motion while retaining visible status updates |
| `SHISAD_TRACE_ENABLED` | Enable trace recording |
| `SHISAD_REQUIRE_LOCAL_ADAPTERS` | Require pre-installed coding-agent binaries; disallow runtime `npx` fetches (`1`/`true`/`yes`) |

UI accessibility notes:

- Presence of the standard `NO_COLOR` variable suppresses palette color in
  chat, the one-shot terminal dashboard, and static web snapshots. Root
  `shisad --no-color ...` does the same for that invocation.
- `SHISAD_REDUCE_MOTION=true` disables optional motion; it does not hide
  connection, lifecycle, or status text.
- `SHISAD_UI_THEME_PATH` and other custom theme-file selectors are not
  accepted. The three built-in names above are the complete supported theme
  configuration surface for this release.

## Channel and Identity Settings

Matrix:

- `SHISAD_MATRIX_ENABLED`
- `SHISAD_MATRIX_HOMESERVER`
- `SHISAD_MATRIX_USER_ID`
- `SHISAD_MATRIX_ACCESS_TOKEN`
- `SHISAD_MATRIX_ACCESS_TOKEN_REF`
- `SHISAD_MATRIX_ROOM_ID`
- `SHISAD_MATRIX_E2EE`
- `SHISAD_MATRIX_TRUSTED_USERS`
- `SHISAD_MATRIX_ROOM_WORKSPACE_MAP`

Discord:

- `SHISAD_DISCORD_ENABLED`
- `SHISAD_DISCORD_BOT_TOKEN`
- `SHISAD_DISCORD_BOT_TOKEN_REF`
- `SHISAD_DISCORD_DEFAULT_CHANNEL_ID`
- `SHISAD_DISCORD_USE_THREADS`
- `SHISAD_DISCORD_TRUSTED_USERS`
- `SHISAD_DISCORD_GUILD_WORKSPACE_MAP`
- `SHISAD_DISCORD_CHANNEL_RULES`

Telegram:

- `SHISAD_TELEGRAM_ENABLED`
- `SHISAD_TELEGRAM_BOT_TOKEN`
- `SHISAD_TELEGRAM_BOT_TOKEN_REF`
- `SHISAD_TELEGRAM_DEFAULT_CHAT_ID`
- `SHISAD_TELEGRAM_TRUSTED_USERS`
- `SHISAD_TELEGRAM_CHAT_WORKSPACE_MAP`

Slack:

- `SHISAD_SLACK_ENABLED`
- `SHISAD_SLACK_BOT_TOKEN`
- `SHISAD_SLACK_BOT_TOKEN_REF`
- `SHISAD_SLACK_APP_TOKEN`
- `SHISAD_SLACK_APP_TOKEN_REF`
- `SHISAD_SLACK_DEFAULT_CHANNEL_ID`
- `SHISAD_SLACK_TRUSTED_USERS`
- `SHISAD_SLACK_TEAM_WORKSPACE_MAP`

Identity gating:

- `SHISAD_CHANNEL_IDENTITY_ALLOWLIST`

Each `*_TOKEN_REF` is a logical O2A credential name resolved only for enabled
adapter construction. It is mutually exclusive with the matching raw token
field, and Slack bot/app references must be distinct. Missing references and
optional channel dependencies degrade that channel without blocking the safe
core daemon. A connector or test target is never an identity grant; configure
an explicit channel `*_TRUSTED_USERS` list or generic allowlist for ingress.

Discord public-channel rules:

- `SHISAD_DISCORD_USE_THREADS` is a boolean and defaults to `false`. When
  enabled, an addressed parent-channel message creates or reuses its Discord
  message thread; existing thread messages stay in that thread, session reuse
  includes the exact thread ID, and outbound delivery does not fall back to the
  parent when a thread target is invalid. The bot needs Create Public Threads
  and Send Messages in Threads permissions. DMs retain their existing flat
  behavior.

- `SHISAD_DISCORD_CHANNEL_RULES` accepts a JSON list of rules. Each rule may set
  `guild_id`, `channels`, `exclude_channels`, `mode` (`mention-only`,
  `read-along`, or `passive-observe`), `public_enabled`, `public_tools`,
  `trusted_guest_users`, `trusted_guest_tools`, `denied_users`,
  `relevance_keywords`, `cooldown_seconds`, and `proactive_marker`.
- `guild_id` must match a concrete guild ID unless you intentionally
  set `guild_id` to `*`. Empty or omitted `channels` means every channel in the
  matching guild except `exclude_channels`; use explicit `channels` for
  include-only public grants. When multiple matching rules have equal
  specificity, later rules override earlier rules.
- Missing rules fail closed to normal allowlist/pairing behavior. Explicit
  channel/user denies win over broad public rules. Public/trusted-guest sessions
  are ephemeral, do not receive owner-private memory context, and only receive
  the small built-in public-tool surface currently accepted by the runtime
  (`web.search`, `web.fetch`, `realitycheck.search`, `realitycheck.read`) when
  those tools are configured and available.

## Assistant, Web, Filesystem, Attachment, Reality Check, and Coding-Agent Settings

Assistant/persona:

- `SHISAD_ASSISTANT_PERSONA_TONE`
- `SHISAD_ASSISTANT_PERSONA_CUSTOM_TEXT`
- `SHISAD_ASSISTANT_PERSONA_SOUL_PATH`
- `SHISAD_ASSISTANT_PERSONA_SOUL_MAX_BYTES`
- `SHISAD_CONTEXT_WINDOW`
- `SHISAD_SUMMARIZE_INTERVAL`
- `SHISAD_MEMORY_AUTO_EXTRACTION_ENABLED`
- `SHISAD_MEMORY_AUTO_EXTRACTION_CONFIDENCE_THRESHOLD`
- `SHISAD_PLANNER_MEMORY_TOP_K`

Memory auto-extraction notes:

- Session-derived conversation summaries can write durable memory by default
  when `memory.write` is available; resulting writes are owner-scoped when the
  session has a complete user/workspace owner tuple.
- Set `SHISAD_MEMORY_AUTO_EXTRACTION_ENABLED=false` to keep ordinary chat turns
  from creating automatic memory writes while leaving explicit memory tools and
  recall available.
- Set `SHISAD_MEMORY_AUTO_EXTRACTION_CONFIDENCE_THRESHOLD` to a value from `0`
  to `1` to discard lower-confidence automatic extraction proposals before
  they are written.

SOUL.md notes:

- `SHISAD_ASSISTANT_PERSONA_SOUL_PATH` points to your persona
  preference file. Its content is treated as trusted persona preference text
  below safety/developer instructions, not as project memory or policy.
- `shisad admin soul update --content ...` replaces that file through the
  admin `SOUL.md` update path. The file may contain personal tone/persona
  preferences and is readable by any user or process with access to the
  configured path. Store project-specific facts in the memory system instead.
- `--expected-sha256` is an optional write precondition for concurrent-edit
  protection; it is not a secret.

Web:

- `SHISAD_WEB_SEARCH_ENABLED`
- `SHISAD_WEB_SEARCH_BACKEND_URL`
- `SHISAD_WEB_FETCH_ENABLED`
- `SHISAD_WEB_ALLOWED_DOMAINS`
- `SHISAD_WEB_TIMEOUT_SECONDS`
- `SHISAD_WEB_MAX_FETCH_BYTES`

Web notes:

- `SHISAD_WEB_SEARCH_BACKEND_URL` must point at a compatible search backend that serves JSON search results over HTTP(S). The current runtime expects a SearxNG-style `/search` endpoint.
- `docs/DEPLOY.md` has an end-to-end SearxNG recipe. The common source-runner
  setting is `SHISAD_WEB_SEARCH_BACKEND_URL=http://127.0.0.1:8080`. Inside the
  shisad container, loopback refers to that container; use an explicitly
  reachable backend service address and allowlist its actual host.
- IP-literal, `localhost`, and `.local` / `.internal` / `.lan` search backend hosts must be present in the effective web allowlist. For local SearxNG runner setups, use `SHISAD_WEB_ALLOWED_DOMAINS=127.0.0.1,localhost` in `runner/.env`; if `SHISAD_WEB_ALLOWED_DOMAINS` is unset, the daemon falls back to policy egress hosts. Public backend hosts do not need an allowlist entry just to run `web.search`, but listing the backend and common result hosts preapproves backend redirects and later `web.fetch` calls.
- Restart the daemon after changing `SHISAD_WEB_*` values. The running daemon reads these variables at startup, so exporting them in a later CLI terminal does not update an existing daemon.
- If `SHISAD_WEB_SEARCH_BACKEND_URL` is unset, `tool.web.search` stays available in the registry but reports `web_search_backend_unconfigured` in live tool-status checks instead of silently locking down the session.
- `search_backend_invalid_json` usually means the backend did not return JSON for `/search?q=...&format=json`; for SearxNG, enable `json` under `search.formats`.

msgvault email:

- `SHISAD_MSGVAULT_ENABLED`
- `SHISAD_MSGVAULT_COMMAND`
- `SHISAD_MSGVAULT_HOME`
- `SHISAD_MSGVAULT_TIMEOUT_SECONDS`
- `SHISAD_MSGVAULT_MAX_RESULTS`
- `SHISAD_MSGVAULT_MAX_BODY_BYTES`
- `SHISAD_MSGVAULT_ACCOUNT_ALLOWLIST`

msgvault notes:

- `email.search` and `email.read` are read-only structured tools requiring
  `email.read` capability. They use the local msgvault CLI with `--local` for
  search/read output; reads also inspect local msgvault archive email metadata.
  shisad does not perform Gmail/IMAP sync and does not copy provider
  OAuth or IMAP credentials into its own credential store in this slice.
- `SHISAD_MSGVAULT_ENABLED=1` enables runtime calls. If it is unset, the tools
  remain registered but return `msgvault_disabled` with setup guidance instead
  of locking down the session.
- `SHISAD_MSGVAULT_HOME` is passed to msgvault as `--home`. Leave it unset to
  use msgvault's default archive location.
- `SHISAD_MSGVAULT_ACCOUNT_ALLOWLIST` accepts CSV or JSON array syntax. When
  set, searches must target a listed account unless exactly one account is
  configured, in which case that account is selected automatically. Message
  reads verify the requested message id is an email row in local msgvault
  archive metadata before reading the matched msgvault internal id; when the
  allowlist is set, reads also use the same account resolution.
- Search output is bounded to metadata and snippets. Message reads omit HTML
  bodies, omit BCC recipient details, include only BCC counts, and truncate
  text bodies to `SHISAD_MSGVAULT_MAX_BODY_BYTES`.
- Email tool output is tainted as both untrusted and sensitive email content.
  Covered write, send, task, reminder, and egress paths still rely on the
  existing taint/PEP confirmation or block behavior; treat
  email content as context, not as user authorization for follow-on actions.
- Email send/reply, calendar read/write, Google Workspace write skills, remote
  msgvault API/MCP transport, and msgvault sync/setup automation are deferred.

Browser:

- `SHISAD_BROWSER_ENABLED`
- `SHISAD_BROWSER_COMMAND`
- `SHISAD_BROWSER_ALLOWED_DOMAINS`
- `SHISAD_BROWSER_TIMEOUT_SECONDS`
- `SHISAD_BROWSER_REQUIRE_HARDENED_ISOLATION`
- `SHISAD_BROWSER_MAX_READ_BYTES`

Browser notes:

- `SHISAD_BROWSER_ENABLED=1` turns on the planner-visible browser tool surface (`browser.navigate`, `browser.read_page`, `browser.screenshot`, `browser.click`, `browser.type_text`, `browser.end_session`).
- `SHISAD_BROWSER_COMMAND` must point at the shisad browser wrapper protocol,
  not the upstream Playwright CLI. For source checkouts, the wrapper is
  `scripts/shisad-playwright-cli.mjs`; set
  `SHISAD_BROWSER_COMMAND=/path/to/shisad/scripts/shisad-playwright-cli.mjs`
  after installing the prerequisites in `docs/runbooks/BROWSER.md`. Neither
  the wheel nor the local container candidate installs the Node wrapper or a
  browser, so artifact installs need an explicit compatible wrapper/runtime;
  a container-mounted wrapper must also be executable by uid/gid `10001`.
- Upstream `playwright` / `npx playwright` is not protocol-compatible with shisad because the daemon passes a shisad session selector (`-s=shisad-...`) and uses wrapper-specific subcommands.
- If `SHISAD_BROWSER_ALLOWED_DOMAINS` is empty, both the runtime browser sandbox policy and the planner/PEP browser tool registry fall back to `SHISAD_WEB_ALLOWED_DOMAINS`.
- `SHISAD_BROWSER_ALLOWED_DOMAINS` and `SHISAD_WEB_ALLOWED_DOMAINS` accept either comma-separated values (`example.com,api.example.com`) or JSON arrays (`["example.com","api.example.com"]`) from environment variables. Prefer the comma-separated form in `runtime.env`, `runner/.env`, and other env files for readability; if you use JSON arrays in a shell-sourced env file, quote the whole value so the inner quotes are preserved.
- `SHISAD_BROWSER_ALLOWED_DOMAINS` acts as an auto-approve/browser-egress scope seed, not a hard deny wall for explicit public-host navigation; the runtime still adds the concrete requested browser host to the per-action sandbox allowlist.
- Hardened browser isolation currently requires literal browser scope entries. If `SHISAD_BROWSER_REQUIRE_HARDENED_ISOLATION=1`, wildcard host patterns in `SHISAD_BROWSER_ALLOWED_DOMAINS` or the `SHISAD_WEB_ALLOWED_DOMAINS` fallback are rejected fail-closed because the connect-path runtime cannot precompute wildcard sibling hosts safely.
- Read-mostly browser actions (`browser.navigate`, `browser.read_page`, `browser.screenshot`, `browser.end_session`) are intended to proceed without confirmation when the destination is authorized. Browser write actions (`browser.click`, `browser.type_text`) are confirmation-gated.
- Loopback/private browser targets remain blocked by the sandbox unless the target host is explicitly allowlisted for the browser surface in the current configuration.
- `SHISAD_BROWSER_REQUIRE_HARDENED_ISOLATION` defaults to `1`. Keep it enabled unless you are deliberately running a non-production browser integration and understand that disabling it weakens the browser isolation boundary.
- `shisad doctor check --component browser` probes the configured command for the shisad wrapper sentinel, verifies that the wrapper can load `@playwright/test`, and reports `browser_command_protocol_incompatible` when the command looks like the real Playwright CLI or another wrapper that does not implement the shisad protocol. It also checks the Playwright browser cache path and reports `browser_cache_not_writable` when the daemon user cannot create/use it.

Browser host prerequisites:

- `bubblewrap` must be installed for the default hardened container sandbox.
- Node.js 22 LTS or newer must be installed with matching `npm`/`npx` to run
  the source-checkout wrapper. On Ubuntu 24.04, the default `nodejs` and `npm`
  packages provide unsupported Node 18; use an operator-approved Node 22+
  installation instead.
- Install the wrapper dependency in the shisad checkout with `npm install @playwright/test`.
- Install both the Chromium browser binary and native shared libraries: `npx playwright install chromium` and `npx playwright install-deps chromium`.
- See `docs/runbooks/BROWSER.md` for a complete setup and protocol reference.

MCP interop:

- `SHISAD_MCP_SERVERS`
- `SHISAD_MCP_TRUSTED_SERVERS`

MCP notes:

- `SHISAD_MCP_SERVERS` accepts a JSON array of server configs. `transport:
  "stdio"` entries require `command: ["executable", "arg1", ...]`; `transport:
  "http"` entries require `url: "http(s)://.../mcp"`.
- `transport: "stdio"` entries can also set `env: {"NAME":"value"}` for
  explicit subprocess environment variables. MCP stdio launches do not inherit
  the daemon's full environment by default. Explicit values can intentionally
  replace a normally filtered variable for that one server, but function-style
  exports are not forwarded.
- MCP server names are normalized to lowercase and must remain unique after
  normalization.
- `SHISAD_MCP_TRUSTED_SERVERS` accepts either a CSV string or JSON array of
  normalized MCP server names. Servers in that allowlist bypass the default
  confirmation gate for external MCP tools, but the tools still remain
  externally sourced and untrusted for planner/runtime tainting purposes.
- Discovered tools register under runtime ids like `mcp.<server>.<tool>`. The
  upstream MCP tool name is preserved separately for transport calls, and MCP
  tools require confirmation by default unless the server name appears in
  `SHISAD_MCP_TRUSTED_SERVERS`.

A2A interop:

- `SHISAD_A2A`

A2A notes:

- `SHISAD_A2A` accepts a JSON object for signed A2A listener, identity, and
  static remote-agent registry configuration. The A2A surface is inbound
  signed external-ingress over direct socket or HTTP transports.
- A minimal config object includes `enabled`, `identity.agent_id`,
  `identity.private_key_path`, `identity.public_key_path`, `listen`, and
  `agents`. Each configured remote agent must provide a fingerprint plus either
  inline `public_key` PEM or `public_key_path`.
- Socket agents use `address: "host:port"` with `transport: "socket"`. HTTP
  agents use full `http(s)://...` URLs with `transport: "http"`.
- `shisad a2a keygen` generates an Ed25519 keypair, writes the private key
  owner-only, and prints the public-key fingerprint for out-of-band exchange.
- `allowed_intents` is enforced fail-closed at A2A ingress. Missing
  `allowed_intents` rejects all requests from that configured remote agent
  until you add explicit grants.
- Configured remote-agent fingerprints must be unique. Shared-key aliases are
  rejected so grants and rate limits remain anchored to one authenticated
  remote principal.
- `rate_limits` enforces per-source budgets keyed on the verified remote
  public-key fingerprint. Defaults: `60/minute`, `600/hour`.
- Each accepted or rejected inbound A2A request emits an
  `A2aIngressEvaluated` audit event with sender identity, intent, outcome, and
  rejection reason when applicable.

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
- `SHISAD_SIGNER_LEDGER_URL`
- `SHISAD_SIGNER_LEDGER_BEARER_TOKEN`
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
- `SHISAD_SIGNER_LEDGER_URL` enables the Ledger hardware device signer backend used for `trusted_display_authorization` (L4) approvals. When unset, the `ledger` signer method stays unavailable. The bridge service (`contrib/ledger-bridge/`) implements the same HTTP contract as the KMS backend and, in the current reference implementation, communicates with a Ledger device via local USB HID.
- `SHISAD_SIGNER_LEDGER_BEARER_TOKEN`, when set, is sent as an `Authorization: Bearer ...` header to the Ledger bridge endpoint. Set the bridge-side `SHISAD_LEDGER_BRIDGE_BEARER_TOKEN` environment variable or `--bearer-token` flag to the same value; the bridge rejects `/sign` and `/extract-key` with HTTP 401 when a token is configured and the header does not match.
- For remote-daemon/local-USB deployments, follow the [Ledger bridge runbook](runbooks/LEDGER-BRIDGE.md) so the bridge stays on loopback or a private tunnel and the remote daemon still verifies signatures against the registered public key.
- The `ledger` backend uses the Ethereum app's `signTypedData` (EIP-712) to render structured action summaries with labeled fields and sign with ECDSA secp256k1. The signed typed data includes the canonical `intent_envelope_hash`, so the signature binds to the full daemon-side `IntentEnvelope` even though the device displays a reduced human-readable projection. Keys registered with `--backend ledger` require `signing_scheme=eip712` and `algorithm=ecdsa-secp256k1`; registrations that request a different Ledger algorithm fail fast.
- The Ledger bridge reports Stax/Flex models as `trusted_device_display`. Nano and unknown models are reported as `opaque_device` with `blind_sign_detected: true`, which drops the verified approval to `bound_approval` (L2) instead of satisfying L4.
- Registered signer public keys still live in the same daemon-owned approval-factor store as TOTP/WebAuthn/helper factors. `L1` encrypts ArtifactLedger blob payloads only; approval-factor and recovery-code at-rest hardening remains follow-on.

Evidence-at-rest notes:

- `SHISAD_EVIDENCE_KMS_URL` enables the remote artifact-crypt boundary used for ArtifactLedger blob payloads. When unset, the shipped default remains plaintext ArtifactLedger blob storage on the daemon filesystem.
- `SHISAD_EVIDENCE_KMS_BEARER_TOKEN`, when set, is sent as an `Authorization: Bearer ...` header to that artifact-crypt endpoint. The daemon emits a startup warning if a bearer token is configured for non-loopback `http://...`; use `https://...` for non-local endpoints so the token is not sent without TLS protection.
- `SHISAD_EVIDENCE_KMS_TIMEOUT_SECONDS` sets the per-request timeout for ArtifactLedger encrypt/decrypt RPCs. Sub-second values are supported down to `0.1` seconds.
- Scope is intentionally narrow and truth-scoped: only blob payload bytes are encrypted. Artifact metadata remains plaintext in `refs_index.json` so ref lifecycle, deduplication, and GC still work. That plaintext metadata includes `ref_id`, `content_hash`, `summary`, `source`, timestamps, taint labels, endorsement state, and storage codec.
- Codec/config drift is non-destructive: if the daemon restarts with a different blob codec than the persisted ref expects (for example encrypted blobs but no `SHISAD_EVIDENCE_KMS_URL`, or plaintext blobs after enabling the evidence KMS path), the ref stays preserved in metadata and remains unreadable until the matching codec boundary is restored.
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
- Non-`ok` responses, malformed JSON, invalid base64, invalid URLs, or invalid UTF-8 plaintext fail closed. New writes degrade to an `[EVIDENCE unavailable ...]` stub for that turn instead of silently downgrading the storage claim.
- Decrypt failures from the remote artifact-crypt boundary do not delete the ref automatically; the daemon preserves the metadata row so the evidence can recover later if the correct key boundary comes back. Proven local corruption cases such as missing blobs or content-hash mismatch still invalidate and drop the ref.

Filesystem/git:

- `SHISAD_ASSISTANT_FS_ROOTS`
- `SHISAD_ASSISTANT_MAX_READ_BYTES`
- `SHISAD_ASSISTANT_GIT_TIMEOUT_SECONDS`

Attachment ingest:

- `SHISAD_ATTACHMENT_MAX_IMAGE_BYTES`
- `SHISAD_ATTACHMENT_MAX_AUDIO_BYTES`
- `SHISAD_ATTACHMENT_MAX_IMAGE_PIXELS`
- `SHISAD_ATTACHMENT_MAX_AUDIO_DURATION_SECONDS`
- `SHISAD_ATTACHMENT_MAX_TRANSCRIPT_CHARS`

Attachment ingest notes:

- `attachment.ingest` reads local files only from `SHISAD_ASSISTANT_FS_ROOTS`.
- The first shipped slice accepts images and voice/audio recordings by bounded
  local path. It stores tainted ArtifactLedger manifests, not raw attachment
  bytes.
- Unsupported, malformed, oversized, or transcript-risky attachments are stored
  as quarantined manifests. Quarantined refs are not readable through the
  default `evidence.read` / `evidence.promote` path.
- `SHISAD_ATTACHMENT_MAX_TRANSCRIPT_CHARS` caps caller-supplied transcript text
  before firewall screening and manifest storage. Oversized transcripts are
  quarantined with `transcript_too_large` and the transcript body is not stored
  in the manifest.
- OCR, provider speech-to-text, channel attachment downloads, email attachment
  export, document parsing, and multimodal model input are follow-on work.

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
| `SHISAD_SECURITY_APPROVAL_FACTOR_STORE_PATH` | Approval-factor and signer-key state path (daemon-owned JSON until at-rest encryption lands) |

The removed `SHISAD_SECURITY_REQUIRE_CONFIRMATION_FOR_WRITES`,
`SHISAD_SECURITY_EGRESS_DEFAULT_DENY`, `SHISAD_SECURITY_CREDENTIAL_STORE_PATH`,
and `SHISAD_SECURITY_AUDIT_LOG_PATH` names had no runtime consumer and are not
accepted as configuration. Confirmation and egress posture come from the
policy bundle; credential/audit storage is constructed by the live daemon.

`SHISAD_UI_THEME_PATH` remains unaccepted because custom theme-file authority
and reload behavior are not defined. `SHISAD_UI_THEME` is live only for the
three built-in palettes documented above.

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
- `*_CAPABILITIES` accepts `context_window_tokens` when the route's total
  context capacity is known and `output_reserve_tokens` (default `1024`). The
  exact remote `shisa_default` planner endpoint/model resolves to a
  16,384-token window unless `context_window_tokens` is explicitly configured;
  endpoint overrides and custom model ids remain unknown by default rather
  than inheriting a guessed limit.
- For a planner route with a known window, shisad estimates the full outbound
  request, including system instructions and tool schemas, and removes bounded
  optional session-context categories when needed. Safety instructions, the
  authenticated current goal, its tainted scaffold copy, trusted frontmatter,
  and enabled tool schemas are retained. If that protected request still does
  not fit, the turn returns an actionable capacity message without making a
  provider call. Recognized provider-reported capacity failures are also
  terminal and do not fall back to another planner with the same oversized
  request.
- Route-local `*_REMOTE_ENABLED` fields accept empty/unset to mean “inherit global”.
- `SHISAD_MODEL_API_KEY` is the generic global override, but preset-native key envs are also recognized.
- `SHISAD_MODEL_API_KEY_REF` is the provider-agnostic logical-reference
  alternative to the global raw key. Route-local alternatives are
  `SHISAD_MODEL_PLANNER_API_KEY_REF`,
  `SHISAD_MODEL_EMBEDDINGS_API_KEY_REF`, and
  `SHISAD_MODEL_MONITOR_API_KEY_REF`. A raw key and its matching reference are
  mutually exclusive. When a reference is explicit, unrelated ambient
  provider keys do not replace it.
- `SHISAD_SECURITY_CREDENTIAL_REFERENCE_STORE_PATH` selects the versioned
  metadata registry, and `SHISAD_SECURITY_CREDENTIAL_SECRET_DIR` selects the
  owner-only local plaintext backend root. Their defaults follow
  `SHISAD_DATA_DIR`; custom paths are explicit operator state.
- Ordinary `shisad doctor check --component provider` reports configuration
  evidence only; a present key is `configured`, not authenticated or verified.
  Run `shisad doctor check --component provider --live` for the opt-in bounded
  planner probe. Use `--timeout` to select a value from 0.1 to 10 seconds.

## Direct Env Reads Outside `BaseSettings`

These are still part of the live surface:

| Env var | Purpose |
|---|---|
| `SHISAD_MEMORY_MASTER_KEY` | Optional memory-encryption secret override |
| `SHISAD_SESSION_ID` | CLI current-session default when a command has no explicit `--session`; otherwise the CLI may use its last-session cache where that command permits it |
| `SHISAD_USER` | CLI owner-scope default used together with `SHISAD_WORKSPACE` when explicit `--user` / `--workspace` flags are absent |
| `SHISAD_WORKSPACE` | CLI owner-scope default used together with `SHISAD_USER`; setting only one of the pair is an error |
| `OPENAI_API_KEY` | OpenAI preset credential discovery |
| `SHISA_API_KEY` | SHISA preset credential discovery |
| `OPENROUTER_API_KEY` | OpenRouter preset credential discovery |
| `GEMINI_API_KEY` | Google OpenAI-compatible preset credential discovery |
| `ANTHROPIC_API_KEY` | Anthropic preset credential discovery for planner/monitor routes |
| Dynamically registered environment locator | A `credential set --backend env --locator NAME` entry reads only the exact registered variable at trusted resolution; status never prints its value |
| `_SHISAD_COMPLETE` | shell-completion internal env, not operator config |

## Opt-In Test / Dev Knobs

These are repo/test helpers, not normal operator runtime config:

| Env var | Purpose |
|---|---|
| `SHISAD_TEST_MODE` | Enables test-only daemon helpers, including reset RPC registration. Never enable on a production daemon. |
| `SHISAD_LIVE_MODEL_TESTS` | opt-in live-model behavioral suite |
| `SHISAD_LIVE_CODING_AGENTS` | opt-in live coding-agent smoke suite |

## Dev Harness Minimum Useful Subset

For local dev work, the runner harness (`runner/harness.sh`) sets sane defaults
automatically. If configuring manually, the core subset is:

```bash
export SHISAD_DATA_DIR="$PWD/.local/shisad-dev"
case "${XDG_RUNTIME_DIR:-}" in
  /*) export SHISAD_SOCKET_PATH="$XDG_RUNTIME_DIR/shisad/control.sock" ;;
  *) export SHISAD_SOCKET_PATH="/tmp/shisad-$(id -u)/control.sock" ;;
esac
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
