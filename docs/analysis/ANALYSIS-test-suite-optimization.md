# Test Suite Optimization Rollout

*Created: 2026-04-14*
*Status: Implemented*

## Scope

Implement the daemon test-efficiency plan for the public repo:

- expand `daemon.reset` into a test-only, full-surface state reset;
- harden the shared daemon harness so failed resets do not cascade into later tests;
- reduce daemon shutdown latency by parallelizing independent teardown work;
- thread a configurable control-plane sidecar startup timeout through test helpers;
- convert safe test modules from per-test daemon startup to shared-daemon reuse;
- add adoption guardrails so new `run_daemon()` / `DaemonServices.build()` test sites do not quietly regress the migration.

This is developer/runtime infrastructure work. It does not change the user-facing
security model or product contract.

## Pre-Analysis

### Design / behavioral contract

`docs/DESIGN-PHILOSOPHY.md` still governs this change: optimization is allowed
only if it preserves the live product contract. Shared-daemon reuse cannot
weaken runtime wiring, skip security checks, or hide state bleed between tests.

### Threat hotspots

- `daemon.reset` is a production footgun unless the RPC is never registered
  outside explicit test mode.
- Reset must cover state that lives outside `DaemonServices`, especially
  handler-owned pending confirmations / lockouts / pairing artifacts.
- Reset must preserve static runtime wiring, including build-time `EventBus`
  subscriptions and route credentials, or post-reset behavior will drift from a
  fresh daemon.
- Shared-daemon fixtures need deterministic recovery after reset failure so one
  bad test cannot poison later tests.

### Runtime wiring checkpoints

- `src/shisad/daemon/runner.py`: conditionally register `daemon.reset`; wrap
  RPCs with activity tracking for reset-idle checks.
- `src/shisad/daemon/services.py`: extend reset coverage, preserve build-time
  identity / credential wiring, parallelize shutdown, and thread the sidecar
  timeout into `start_control_plane_sidecar()`.
- `src/shisad/daemon/handlers/_impl.py` and
  `src/shisad/daemon/handlers/_impl_admin.py`: add handler-layer reset and
  quiescence validation.
- `src/shisad/security/control_plane/sidecar.py` and
  `src/shisad/core/config.py`: make sidecar startup timeout configurable from
  `DaemonConfig`.
- `tests/helpers/daemon.py` and converted integration modules: shared-daemon
  reset/restart flow.

### Validation plan

Before changes:

- run the currently existing daemon-reset / daemon-services / sidecar tests
  individually to capture a baseline.
- run the candidate shared-daemon integration files in their current per-test
  mode to confirm their pre-change behavior.

After changes:

- rerun touched tests individually;
- rerun grouped combinations and converted modules end-to-end to verify reset
  isolation;
- run static checks (`ruff`, `mypy`);
- run `tests/behavioral/ -q`;
- run an isolated live runner verification because this changes runtime-facing
  daemon wiring.

## Migration Ledger

| Module | Status | Notes |
| --- | --- | --- |
| `tests/integration/test_task_ledger_scaffold.py` | converted | Module-scoped shared daemon via `tests/helpers/daemon.py`; reset reuses the daemon when quiescent and restarts it when tests leave reset-worthy pending state behind. |
| `tests/integration/test_handler_integration.py` | converted (partial) | First three tests now share a module-scoped daemon; the permissive-policy posture test stays per-test because it intentionally changes policy posture. |
| other `run_daemon()` / `DaemonServices.build()` sites | blocked | Need explicit review for policy/config drift (`assistant_fs_roots`, channel config, path assertions, restart semantics, or direct `DaemonServices.build()` coverage). |

## Implemented Scope

- `daemon.reset` is registered only when `DaemonConfig.test_mode` is enabled and now routes through the handler-layer reset path instead of clearing only `DaemonServices`.
- Reset coverage now wipes service-layer mutable state plus handler-owned pending approvals, 2FA enrollment state, lockout state, pairing artifacts, and runtime counters while preserving static runtime wiring such as route credentials, event subscriptions, and config-seeded identity allowlists.
- `DaemonServices.shutdown()` now closes embeddings, channel connections, sidecar, approval web, and control server concurrently.
- `tests/helpers/daemon.py` now defaults test harnesses to test mode, threads the sidecar startup timeout through the harness config, and exposes a shared-daemon controller with reset-or-restart semantics for module-scoped reuse.
- Added `scripts/test_daemon_site_guard.py` plus `tests/fixtures/daemon_site_baseline.json` and wired the guard into CI so new `run_daemon()` / `DaemonServices.build()` test sites cannot grow unnoticed.

## Current Baseline

- `run_daemon()` call sites under `tests/`: 90
- `DaemonServices.build()` call sites under `tests/`: 34
