# Changelog

All notable changes to shisad are documented in this file.

This changelog is release-oriented: a new section is added when cutting a
release tag. There is no standing "Unreleased" section.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows semver (see `docs/PUBLISH.md` for policy and style guide).

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
  dynamic remote tool discovery is not yet supported (planned for v0.6.3).

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

[0.6.1]: https://github.com/shisa-ai/shisad/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/shisa-ai/shisad/compare/v0.5.2...v0.6.0
[0.5.2]: https://github.com/shisa-ai/shisad/compare/v0.5.1...v0.5.2
[0.5.1]: https://github.com/shisa-ai/shisad/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/shisa-ai/shisad/releases/tag/v0.5.0
