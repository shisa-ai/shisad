# Changelog

All notable changes to shisad are documented in this file.

This changelog is release-oriented: a new section is added when cutting a
release tag. There is no standing "Unreleased" section.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows semver (see `docs/PUBLISH.md` for policy).

## [0.6.0] - 2026-04-03

### Added

- Formal COMMAND/TASK orchestration runtime with isolated task sessions,
  taint-safe handoffs, a TASK close-gate self-check, restart-safe session
  migration/archival flows, task-scoped credential refs, typed boundary
  validation, live resource-scope enforcement, and a structured ArtifactLedger
  with approval provenance.
- Web/browser tool-surface expansion: skill-declared tools via
  `ToolRegistry`, `web.search`, evidence-wrapped `web.fetch`, text-first
  evidence rendering in the terminal UI, and the baseline browser toolkit
  (`browser.navigate`, `browser.read_page`, `browser.screenshot`,
  `browser.click`, `browser.type_text`, `browser.end_session`).
- Supply-chain and release hardening for the shipped tool surface: persisted
  schema hashes for reviewed local skill tools, dependency-review and zizmor
  CI gates, pinned GitHub Actions, and the first trusted-publishing workflow
  with SBOM generation and attestations.

### Security

- Browser writes are confirmation-gated and bound to the approved page/source
  context, while hardened browser isolation now defaults fail-closed and
  rejects wildcard browser scope that cannot be safely enforced.
- Evidence refs are restart-stable, cross-session isolated, terminal-safe, and
  continue to keep large untrusted content on the extractive/tainted path by
  default.
- Runtime skill authorization now rejects revoked or drifted artifacts, and
  dynamic remote tool discovery remains explicitly unsupported until the later
  MCP/A2A interop lane.

### Changed

- Public operator docs now truth-scope the browser/web status surface, channel
  evidence rendering contract, and current release roadmap after the
  `v0.6.0` orchestration/tooling baseline.

## [0.5.2] - 2026-04-01

### Fixed

- Added `[project.urls]` to `pyproject.toml` so PyPI links to the GitHub repo,
  issues, and changelog.
- Added `license` field (Apache-2.0) to `pyproject.toml`.

## [0.5.1] - 2026-04-01

### Added

- Auto-detect fallback API key (`ANTHROPIC_API_KEY`) when `SHISA_API_KEY` is
  not set, reducing first-run friction.
- Supply chain dependency audit map (`docs/AUDIT-supply-chain.md`).
- `CHANGELOG.md` and `docs/PUBLISH.md` release checklist.
- First PyPI publication to claim the `shisad` package name.

### Security

- Tightened dependency pinning and CI install controls (hash-verified installs,
  stricter version bounds).

### Fixed

- `__init__.py` version string synced to match `pyproject.toml` (was stuck at
  0.3.4).

## [0.5.0] - 2026-03-30

Initial public release.

### Highlights

- **Security-first agent framework** with per-call policy enforcement pipeline
  (PEP), prompt injection defense, and data exfiltration prevention.
- **Sandbox execution stack** with namespace isolation, filesystem jails, and
  fail-closed runtime guards.
- **Control plane** with hot-reloadable skills/plugins, connection management,
  and session lifecycle.
- **Defense in depth**: multi-layer security (M0-M6) covering auth, egress
  auditing, supply-chain hardening, multi-encoding injection defense, and
  adversarial gates.
- **Structured memory** with semantic search.
- **Observability**: audit trails, anomaly detection, training-ready LLM trace
  recorder.
- **End-to-end demo** script and runner harness for live verification.

[0.6.0]: https://github.com/shisa-ai/shisad/compare/v0.5.2...v0.6.0
[0.5.2]: https://github.com/shisa-ai/shisad/compare/v0.5.1...v0.5.2
[0.5.1]: https://github.com/shisa-ai/shisad/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/shisa-ai/shisad/releases/tag/v0.5.0
