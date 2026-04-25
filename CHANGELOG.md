# Changelog

All notable changes to shisad are documented in this file.

This changelog is release-oriented: a new section is added when preparing or
cutting a release tag. Pre-publish release content is marked explicitly and is
left unlinked until the tag exists. There is no standing "Unreleased" section.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows semver (see `docs/PUBLISH.md` for policy and style guide).

## [0.7.1] - Unreleased

### Fixed

- **The chat TUI now renders assistant Markdown instead of showing Markdown
  punctuation as plain text.** Assistant replies render with Markdown layout,
  and the chat entry box wraps longer prompts, expands while drafting, and
  collapses after submit.

## [0.7.0] - 2026-04-25

### Added

- **Structured long-term memory now has separate surfaces for identity, active
  work, recall, reusable skills, and evidence.** The assistant can keep
  user-approved identity and preference memory available across sessions, track
  active threads and waiting-on items, surface explicit source reads, and
  expose reusable skills without mixing those surfaces together.

- **The assistant can propose new memories and ask you to confirm them before
  they become trusted memory.** Identity candidates, strong memory updates,
  and queued skill suggestions now stay in review flows until you approve them
  from a trusted context instead of silently entering live recall or
  invocation.

- **A derived knowledge graph and consolidation pass are available through the
  live control surface.** Shisad can query and export the current graph view,
  detect strong updates, flag contradictions, and record auditable merge,
  quarantine, and confirmation events without turning the graph into
  authoritative state.

### Changed

- **Memory now lives in a local SQLite backend with versioned entries and audit
  events.** Existing memory callers keep the same public recall interface, but
  the storage layer now records typed entry metadata, trust fields, review
  state, workflow state, supersede history, and explicit ingress handles.

- **Recall and active context are filtered more aggressively by trust, scope,
  and workflow state.** Pending-review items stay out of normal recall,
  identity only accepts trusted approved entries, and active-attention content
  stays separate from the trusted metadata that selects it.

### Security

- **Every memory write records its ingress handle and trust tier.** When you
  inspect a memory entry you can see whether it came from a trusted command,
  an untrusted external channel, a tool result, or a consolidation pass, and
  untrusted sources cannot silently write into elevated memory surfaces.

- **Pending-review memories and skills stay out of default recall and
  invocation paths.** Unconfirmed writes from public channels, external
  content, or tool output no longer leak into trusted memory, active identity,
  or skill invocation until you promote them explicitly.

- **Consolidation can suggest changes but cannot silently promote trust.**
  Duplicate cleanup, contradiction tracking, archive/quarantine decisions, and
  strong-update proposals all remain auditable low-trust events until a user
  confirmation path stamps the promoted result.

- **The Ledger bridge's transitive `axios` lock now resolves to `1.15.2`.** The
  `contrib/ledger-bridge/` lockfile previously resolved `axios@1.13.5` through
  `@ledgerhq/*`, which is affected by CVE-2025-62718 (`NO_PROXY` hostname
  normalization bypass → SSRF) and CVE-2026-40175 (CRLF header injection →
  IMDSv2 bypass when combined with prototype pollution). The bridge now uses an
  npm `overrides` entry to require `axios@^1.15.2`; the committed lockfile
  resolves that range to `axios@1.15.2` and `proxy-from-env@2.1.0`.

## [0.6.7.1] - 2026-04-23

### Fixed

- **Ledger Nano X now round-trips on Linux.** On Linux, the bridge was
  sometimes picking the Nano X's FIDO/U2F HID interface instead of the
  APDU interface, which made the first transaction request hang. The
  bridge now filters Ledger HID interfaces by their APDU usage page on
  Linux, matching what Ledger's own transport already does on macOS and
  Windows. Stax and Flex users were not affected — those models only
  expose the APDU interface.

[0.6.7.1]: https://github.com/shisa-ai/shisad/compare/v0.6.7...v0.6.7.1

## [0.6.7] - 2026-04-21

### Added

- **See and approve transactions on compatible Ledger displays.**
  When a compatible Ledger signer key is registered, shisad can send
  the transaction to the device over the local USB bridge service and
  wait for you to read it on the Ledger's screen and physically
  confirm. Because the display and confirm button are on the hardware,
  a compromised host can't change what you're approving behind the
  scenes.
  - Configure with `SHISAD_SIGNER_LEDGER_URL` and register the key
    with `shisad signer register --backend ledger`.
  - Ledger is the first hardware device on shisad's generic
    trusted-display signer interface. The same interface (a local
    HTTP bridge that shisad signs against) already backs the KMS
    (Key Management Service) signer and is the path for adding other
    hardware wallets later.
  - `v0.6.7` ships before a maintainer-validated device and firmware
    compatibility matrix; that follow-up is tracked for `v0.6.7.1`.

### Security

- **Ledger approvals step down when the device can't show you what
  you're signing.** If the Ledger reports blind-signing mode or an
  unreadable transaction, shisad treats the approval as lower-trust
  instead of claiming you verified it on the hardware screen.

### Fixed

- **Peer-credential enforcement works on macOS.** When shisad runs on
  macOS, the daemon's Unix-socket peer check previously used a
  Linux-only syscall, so it couldn't read the uid or pid of clients
  connecting to the daemon. The daemon now uses the Darwin
  peer-credential syscalls instead.

- **Public docs and CHANGELOG now address end-users as "user", not "operator".**
  The README, CHANGELOG, 2FA guide, env-var reference, and other
  user-facing docs were inconsistent about how they addressed the
  reader. "Operator" still appears in deployment, admin, runbook, and
  threat-model docs where it names a distinct role. Prior CHANGELOG
  sections were also updated so readers don't hit the old term when
  scanning release history — the `[X.Y.Z]` sections on `main` now
  differ slightly from the frozen GitHub Release notes at each tag.

Thanks @GuitareCiel from Ledger for contributing shisad's first external pull
request.

## [0.6.6] - 2026-04-19

### Added

- **Image and voice recordings can be sent as attachments.** The daemon
  ingests local attachment paths with size caps and format validation, so
  large or malformed files are rejected cleanly before reaching the planner.

- **Read and search local email through the assistant.** A new
  MsgVault-backed email toolkit lets the assistant search configured local
  mail archives and read individual messages. When you configure
  `SHISAD_MSGVAULT_ACCOUNT_ALLOWLIST`, requests are scoped to granted accounts
  before reaching the archive.

- **Discord public channels now have per-channel policies.** Configure whether
  shisad chats, reads along quietly, or stays passive in each public channel,
  while public-channel sessions exclude owner-private conversation context.

- **`SOUL.md` customizes the assistant's persona.** Put `SOUL.md` in the
  user config path and the planner layers it in as trusted persona
  preferences below safety and developer instructions. Updates go through a
  dedicated admin edit path from a clean session, so injected content cannot
  rewrite persona mid-conversation.

### Security

- **Attachment ingest is bounded and validated.** Uploads hit size limits
  before decoding, audio ID3 tags are validated, and malformed files are
  quarantined rather than passed on.

- **Email reads validate local message IDs before reading.** MsgVault tools
  resolve message IDs against email metadata and compare IDs exactly before
  reading the matched archive record. When
  `SHISAD_MSGVAULT_ACCOUNT_ALLOWLIST` is set, reads also use that account
  resolution; when MsgVault is disabled, email reads are refused outright.

- **Discord DMs stay fail-closed.** Direct messages require an explicit trust
  grant; granting access to a public channel does not implicitly open DMs.

- **`SOUL.md` edits run from a clean admin session.** Persona updates are
  proposed from a fresh context rather than replaying the current conversation,
  and they go through a narrow admin path rather than general filesystem
  writes. Project-specific facts are steered toward the memory system instead
  of being silently appended to persona text.

### Fixed

- **Tool-only turns no longer go silent.** When a turn runs tools but produces
  no assistant text, shisad synthesizes a short summary of what ran so you can
  see what happened instead of getting an empty reply.

- **Follow-up turns keep same-session evidence.** Evidence refs from previous
  tool-backed turns are carried forward in the same session, so a follow-up can
  use the source envelope behind earlier results instead of relying only on a
  prose recap.

## [0.6.5] - 2026-04-17

### Added

- **External tool servers can connect via the Model Context Protocol (MCP).**
  Configure one or more MCP servers — stdio subprocesses or HTTP endpoints —
  through `SHISAD_MCP_SERVERS`, and the daemon discovers their tools at
  startup. Discovered tools appear in sessions as `mcp.<server>.<tool>` and
  work like built-in tools. If a configured server is unreachable, the daemon
  continues without it.

- **External agents can send signed requests over socket or HTTP.** A new A2A
  listener accepts Ed25519-signed requests from registered remote agents,
  verifies identity and intent, and routes accepted work into a session.
  Operators define which agents can connect and what they can ask for.
  Configure via `SHISAD_A2A`.

- **`shisad a2a keygen` generates an identity keypair.** Run it once to
  create the Ed25519 keys the daemon needs for A2A signing and verification.
  The command prints the public-key fingerprint for out-of-band exchange with
  remote operators.

- **`shisad restart --fresh-config` reloads environment on restart.** Changed
  environment variables take effect immediately instead of requiring a manual
  stop-then-start cycle. The prior configuration is saved as an owner-only
  snapshot before the reload; that backup can contain secrets and should be
  handled accordingly.

### Security

- **MCP tools require confirmation by default.** Unless a server appears in
  `SHISAD_MCP_TRUSTED_SERVERS`, every tool call from that server asks for
  your approval before executing. Trusted servers skip the prompt, but
  their outputs are still treated as external input for screening purposes.

- **MCP tool definitions are validated before registration.** Parameter names,
  types, enum values, and descriptions are screened for injection patterns at
  startup. Tools that fail validation are rejected. Subprocess-based MCP
  servers launch with a sanitized environment allowlist instead of inheriting
  the daemon's full environment by default, but they are not sandboxed and
  still run with the daemon's OS privileges.

- **A2A requests are cryptographically verified.** Every inbound request must
  carry a valid Ed25519 signature matching the agent's registered public-key
  fingerprint. Unsigned envelopes, signature mismatches, and replayed messages
  are rejected.

- **A2A access is fail-closed.** Each remote agent can only send requests for
  intents you have explicitly allowed. Omitting the allowlist means
  zero access until you add grants. Per-agent rate limits (default
  60/min, 600/hour) are enforced on the verified cryptographic identity to
  prevent abuse.

- **Every A2A ingress decision is audited.** Accepted requests, rejections,
  and rate-limit violations emit structured audit events with sender identity,
  intent, outcome, and reason.

### Changed

- **Startup logs show resolved configuration.** The daemon now logs which
  capabilities are active at startup — web search, web fetch, filesystem
  roots, backend URL — so misconfigurations surface immediately instead of at
  first tool call.

- **Operator docs cover MCP and A2A setup.** `docs/DEPLOY.md` and
  `docs/ENV-VARS.md` include configuration examples and trust-model
  explanations for both new interoperability features.

## [0.6.4] - 2026-04-13

### Security

- **Prompt-injection screening now runs through one scanner.** The daemon
  firewall and the analyzer path now share `textguard` for structural
  detection, so the same prompt-injection checks apply across both surfaces
  instead of drifting between separate implementations.
- **Hidden-text and encoded-input detection is broader.** The new scanner
  brings deeper decode coverage and stronger unicode normalization while
  shisad keeps the split-base64 and legacy analyzer compatibility shims it
  still needs for existing workflows.
- **Runtime rule sourcing is simpler and harder to drift.** The daemon
  validates textguard's bundled YARA backend at startup and no longer ships a
  second copied local rule set.

### Changed

- **PromptGuard stays optional.** Base installs now include `textguard[yara]`,
  while local PromptGuard runtime checks remain opt-in through the
  `security-runtime` dependency group for source checkouts or the
  `shisad[promptguard]` extra for package installs.
- **Operator status reflects bundled-rule provenance explicitly.**
  `daemon.status` now reports that the old local security-asset copy is gone
  and that the runtime is using bundled rules.

## [0.6.3] - 2026-04-12

### Added

- **Pending approvals now show what to do next.** When an action needs your
  approval, you see a preview of what it wants to do and the exact commands to
  approve or reject it.
- **TOTP approvals work from chat.** You can enter a TOTP code in the same
  conversation instead of switching to the SSH CLI.
- **TOTP enrollment shows a scannable QR code.** The CLI renders a QR code
  when possible and still prints the raw `otpauth://` URI as a fallback.
- **Anthropic provider preset.** Setting `ANTHROPIC_API_KEY` now configures
  planner and monitor routes without accidentally enabling an incompatible
  embeddings route.

### Fixed

- **Creating todos, notes, and reminders from the CLI no longer asks for
  unnecessary confirmation.** When PromptGuard content safety was enabled, its
  injection-detection score consistently came back slightly above zero on
  direct user input, which caused the system to treat even simple user
  commands like "create a todo" as needing approval. The content safety
  classifier now skips the neural-net check on direct user input — the user is
  the trust root, not an attack surface. Pattern-based detection still runs
  for telemetry.
- **Confirmation replies no longer create new actions.** Typing `confirm 1`,
  `y`, `yes`, a bare number, or `reject` is now recognized as a command
  instead of being sent to the planner as a new request.
- **Stale pending actions are cleaned up on restart.** Old pending rows that
  lost their approval envelope or were locked out of their confirmation method
  no longer keep appearing in the pending list.
- **Terminal replies keep readable line breaks.** Markdown-style responses no
  longer collapse into a single hard-to-read line.
- **Missing model configuration gives useful guidance.** When no language
  model is configured, the error message tells you what to set up instead of
  echoing a fake response.

### Changed

- **Startup and doctor output are more helpful.** `shisad doctor` works
  without a subcommand, missing filesystem roots or embeddings routes are
  easier to spot, overridden presets are labeled as custom, and missing chat
  dependencies point to the `shisad[chat]` install extra.
- **Tools shown to the planner match what's actually available.** When
  filesystem or git roots are not configured, those tools are no longer
  advertised to the planner as usable.

### Security

- **Delegated task scopes are fenced more tightly.** File paths, git refs,
  extensionless filenames, semantic IDs, and numeric chat-thread IDs now stay
  in their correct resource scope instead of accidentally authorizing a
  different kind of resource.
- **CLI convenience skips only low-risk internal bookkeeping.** Creating notes,
  todos, and reminders from a clean CLI session skips the confirmation prompt,
  but suspicious content, untrusted session history, external side effects, and
  stronger policy requirements still go through normal approval.

## [0.6.2] - 2026-04-09

### Added

- **Sensitive actions can require stronger approvals.** Operators can now step
  up from the original software confirmation prompt to TOTP re-auth,
  WebAuthn/passkeys, local-helper approvals, or signer-backed authorization
  depending on policy and risk.
- **Private and SSH-only deployments can approve actions without bouncing to a
  browser.** `shisad-approver` adds a local helper path for stronger approval
  flows on locked-down hosts.
- **There is now a dedicated end-user 2FA guide.** `docs/2FA.md` explains the
  shipped TOTP setup and confirmation experience in plain user-facing terms.

### Security

- **Approval decisions are bound to the exact action the user reviewed.** The
  daemon now records stronger approval metadata, explicit fallback rules, and
  replay-resistant approval/signer evidence in the audit trail.
- **Evidence blobs can be encrypted at rest when an external artifact-KMS is
  configured.** Stored blob bytes stop being plaintext on disk, recoverable
  refs stay available for later recovery, and `evidence.read` /
  `evidence.promote` still work through the live runtime.
- **Signer-backed approvals are verified locally against registered public
  keys.** The daemon no longer has to trust a remote signer service's summary
  of what was approved.

### Changed

- **Public docs now match the shipped v0.6.2 trust model.** The roadmap,
  deployment docs, and user docs now reflect what is actually shipped in
  the approval/key-boundary lane and what remains follow-on work.

## [0.6.1] - 2026-04-05

### Security

- **Security analysis runs in a separate process from the main daemon.** If
  one is compromised, the other is not directly reachable.
- **ML-based injection screening for untrusted content.** Tool arguments and
  untrusted inputs now pass through a PromptGuard 2 classifier before the
  agent can act on them.
- **Unicode-steganography detection works in the shipped build.** The YARA
  rule for hidden-character detection was broken in prior releases due to a
  build issue; it now compiles and runs correctly.
- **You get alerts when denied actions repeat.** When the daemon denies
  a suspicious action (e.g., an unexpected capability request or outbound
  connection), it now logs structured details and warns you once the
  pattern crosses a configurable threshold — previously these were silently
  dropped.
- **Tool actions are checked against what the user actually asked for.** Before
  executing a tool, the runtime verifies the action traces back to the user's
  request. Reads without a clear link are routed to user confirmation; writes
  without a clear link are blocked.
- **Subtasks can inherit their parent session's approved scope.** When a parent
  session is still clean, delegated subtasks reuse its approved resource scope
  instead of requiring re-confirmation for every file access.
- **Modified skill tools are rejected with an explanation.** If a skill's tools
  have changed since they were last reviewed, the daemon logs why the tool was
  dropped instead of silently ignoring it.

### Changed

- **Changelog now follows end-user-facing style guidelines.** See
  `docs/PUBLISH.md` for the principles; the short version is: plainly state
  how functionality has changed, not how it's built internally.

## [0.6.0] - 2026-04-03

### Added

- **Multi-step task orchestration.** The agent can now delegate work to
  separate task sessions with safe data handoffs, result validation, and
  credential scoping — a long-running task can't leak context or credentials
  back to the main session.
- **Session migration and archival.** Sessions survive daemon restarts with
  their security state intact, and completed sessions can be exported/imported
  with integrity checks.
- **Artifact tracking with approval history.** Delegated task outputs are
  tracked in a structured ledger that records who approved what and when.
- **Web search tool** (`web.search`) for querying the web from within a
  session (requires a configured search backend).
- **Web fetch tool** (`web.fetch`) for retrieving web pages, with content
  stored as evidence references to keep large untrusted payloads out of the
  main conversation context.
- **Browser automation tools**: `browser.navigate`, `browser.read_page`,
  `browser.screenshot`, `browser.click`, `browser.type_text`, and
  `browser.end_session` for interacting with web pages directly (requires
  `SHISAD_BROWSER_ENABLED=1` and a configured browser command).
- **Web content rendered as text in the terminal** — fetched pages and browser
  reads display as readable text rather than raw HTML.
- **Skill tool integrity checks.** Local skill tools are validated against
  persisted schema hashes — modified or revoked tools are rejected at runtime.
- **Hardened release pipeline.** Releases now use PyPI OIDC trusted publishing
  with SBOM generation and provenance attestations.
  - Dependency-review and zizmor CI gates added.
  - GitHub Actions pinned to SHA digests.
  - `SHISAD_REQUIRE_LOCAL_ADAPTERS` env var locks down runtime adapter
    downloads.

### Security

- **Browser writes require user confirmation** and are scoped to the approved
  page context.
- **Hardened browser isolation is on by default.** Wildcard browser scope
  entries are rejected because they can't be safely enforced.
- **Evidence references persist across restarts and sessions**, keeping large
  untrusted content out of the main conversation context by default.
- **Skill authorization rejects modified or revoked artifacts** at runtime;
  dynamic remote tool discovery remains out of scope for this release line.

### Changed

- Updated public docs (`ROADMAP.md`, `TOOL-STATUS.md`) to reflect actual
  browser and web tool status after the v0.6.0 release.

## [0.5.2] - 2026-04-01

### Fixed

- Added project URL links to `pyproject.toml` so PyPI shows links to the
  GitHub repo, issues, and changelog.
- Added `license` field (Apache-2.0) to `pyproject.toml`.

## [0.5.1] - 2026-04-01

### Added

- **Automatic API key fallback.** If `SHISA_API_KEY` is not set, shisad
  auto-detects `ANTHROPIC_API_KEY`, reducing first-run friction.
- Supply-chain dependency audit map (`docs/AUDIT-supply-chain.md`).
- `CHANGELOG.md` and release checklist (`docs/PUBLISH.md`).
- First PyPI publication to claim the `shisad` package name.

### Security

- Tightened dependency pinning and CI install controls (hash-verified installs,
  stricter version bounds).

### Fixed

- Version string in `__init__.py` synced to match `pyproject.toml` (was stuck
  at 0.3.4).

## [0.5.0] - 2026-03-30

Initial public release.

### Highlights

- **Security-first agent framework** with per-call policy enforcement — every
  tool call is checked against the security policy before execution.
- **Sandbox execution** with namespace isolation, filesystem jails, and
  fail-closed runtime guards.
- **Hot-reloadable skills and plugins** managed by the control plane.
- **Multi-layer security** covering auth, egress auditing, supply-chain
  hardening, multi-encoding injection defense, and adversarial gates.
- **Structured memory** with semantic search.
- **Audit trails** and anomaly detection, with training-ready LLM trace
  recording.
- **End-to-end demo** script and runner harness for live verification.

[0.7.0]: https://github.com/shisa-ai/shisad/compare/v0.6.7...v0.7.0
[0.6.7]: https://github.com/shisa-ai/shisad/compare/v0.6.6...v0.6.7
[0.6.6]: https://github.com/shisa-ai/shisad/compare/v0.6.5...v0.6.6
[0.6.5]: https://github.com/shisa-ai/shisad/compare/v0.6.4...v0.6.5
[0.6.4]: https://github.com/shisa-ai/shisad/compare/v0.6.3...v0.6.4
[0.6.3]: https://github.com/shisa-ai/shisad/compare/v0.6.2...v0.6.3
[0.6.2]: https://github.com/shisa-ai/shisad/compare/v0.6.1...v0.6.2
[0.6.1]: https://github.com/shisa-ai/shisad/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/shisa-ai/shisad/compare/v0.5.2...v0.6.0
[0.5.2]: https://github.com/shisa-ai/shisad/compare/v0.5.1...v0.5.2
[0.5.1]: https://github.com/shisa-ai/shisad/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/shisa-ai/shisad/releases/tag/v0.5.0
