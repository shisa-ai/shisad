# Changelog

All notable changes to shisad are documented in this file.

This changelog is release-oriented: a new section is added when cutting a
release tag. There is no standing "Unreleased" section.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows semver (see `docs/PUBLISH.md` for policy and style guide).

## [0.6.1] - 2026-04-05

### Security

- **Control-plane analysis is isolated from the main daemon path.** Runtime
  security analysis now runs behind a minimal sidecar boundary so compromise
  of one lane has less direct reach into the other.
- **PromptGuard 2 now screens high-risk content paths.** Untrusted content and
  tool arguments go through the new ML classifier before they reach the live
  execution boundary.
- **The shipped unicode-steganography detector now matches the documented
  runtime.** The released YARA rulepack no longer depends on a broken compile
  path for that detection.
- **Repeated suspicious denied actions raise warnings instead of silently
  disappearing.** The daemon now records structured deny metadata and alerts
  operators when capability probes, unattributed egress probes, or taint
  bypass attempts cross the configured threshold.
- **Risky tool actions must trace back to committed intent.** The runtime now
  checks a Tool Dependency Graph before execution, routes missing-path reads
  to confirmation, and blocks missing-path side effects.
- **Delegated TASK work can inherit trusted scope from a clean COMMAND
  session.** When the parent COMMAND context is still clean, its declared
  resource scope becomes a first-class runtime root instead of forcing vague
  tasks through string matching or unnecessary confirmation.
- **Reviewed skill-tool drift is visible instead of silent.** Modified
  reviewed skill tools still fail closed on restart, and the daemon now emits
  a metadata-only audit event explaining why the tool was dropped.

### Changed

- **Release notes are now written for operators, not just contributors.**
  `CHANGELOG.md` and `docs/PUBLISH.md` now treat release notes as user-facing
  explanations of what each version adds, changes, or hardens.

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
