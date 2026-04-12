# Changelog

All notable changes to shisad are documented in this file.

This changelog is release-oriented: a new section is added when preparing or
cutting a release tag. Pre-publish release content is marked explicitly and is
left unlinked until the tag exists. There is no standing "Unreleased" section.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows semver (see `docs/PUBLISH.md` for policy and style guide).

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
  injection-detection score (always slightly above zero for any input) caused
  the system to treat even simple operator commands like "create a todo" as
  needing approval. The content safety classifier now skips the neural-net
  check on direct operator input — the operator is the trust root, not an
  attack surface. Pattern-based detection still runs for telemetry.
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
  operator docs, and user docs now reflect what is actually shipped in the
  approval/key-boundary lane and what remains follow-on work.

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
- **Operators get alerts when denied actions repeat.** When the daemon denies
  a suspicious action (e.g., an unexpected capability request or outbound
  connection), it now logs structured details and warns operators once the
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
  isolated task sessions with safe data handoffs, result validation, and
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
  untrusted content isolated from the main conversation by default.
- **Skill authorization rejects modified or revoked artifacts** at runtime;
  dynamic remote tool discovery is not yet supported and remains planned for a
  future remote-tool interop lane.

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

[0.6.3]: https://github.com/shisa-ai/shisad/compare/v0.6.2...v0.6.3
[0.6.2]: https://github.com/shisa-ai/shisad/compare/v0.6.1...v0.6.2
[0.6.1]: https://github.com/shisa-ai/shisad/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/shisa-ai/shisad/compare/v0.5.2...v0.6.0
[0.5.2]: https://github.com/shisa-ai/shisad/compare/v0.5.1...v0.5.2
[0.5.1]: https://github.com/shisa-ai/shisad/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/shisa-ai/shisad/releases/tag/v0.5.0
