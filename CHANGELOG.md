# Changelog

All notable changes to shisad are documented in this file.

This changelog is release-oriented: a new section is added when cutting a
release tag. There is no standing "Unreleased" section.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows semver (see `docs/PUBLISH.md` for policy).

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

[0.5.1]: https://github.com/shisa-ai/shisad/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/shisa-ai/shisad/releases/tag/v0.5.0
