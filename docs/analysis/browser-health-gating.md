# Browser Health Gating Worklog

## Scope

Fix the runtime-facing browser availability bug exposed by the Tabelog reservation test: `shisad status` and planner tool registration can advertise browser tools even when `doctor` already reports the configured browser command as unusable.

## Pre-Analysis

- Product contract: missing or misconfigured integrations must produce actionable diagnostics and must not dead-end normal user tasks.
- Runtime hotspot: `DaemonServices.build()` registers planner-visible browser tools from `browser_enabled`, while `BrowserToolkit.doctor_status()` can independently report `misconfigured`.
- Expected behavior: browser tools are planner-visible only when the browser runtime health check is `ok`; otherwise web/search/fetch tools remain available and status surfaces the browser diagnostic.
- Validation scope: targeted daemon-service/tool-registry tests, browser toolkit tests, static checks, first-principles behavioral gates, and live runner doctor/status evidence.
- Cleanup backlog: no touched-area cleanup or TODO backlog docs found under `docs/`.

## Validation Log

- Test-first check before implementation:
  `uv run pytest tests/unit/test_daemon_services.py -k 'browser_registry_falls_back_to_web_allowlist or misconfigured_runtime_suppresses_browser_tools' -q`
  failed as expected with `AttributeError: 'DaemonServices' object has no attribute 'browser_status'`.
- Focused daemon-service regression:
  `uv run pytest tests/unit/test_daemon_services.py -k 'browser_registry_falls_back_to_web_allowlist or misconfigured_runtime_suppresses_browser_tools' -q`
  passed: `2 passed, 54 deselected`.
- Browser and daemon-service unit coverage:
  `uv run pytest tests/unit/test_daemon_services.py tests/unit/test_browser_toolkit.py -q`
  passed: `240 passed`.
- Static checks:
  `uv run ruff check src/ tests/ scripts/` passed.
- Static typing:
  `uv run mypy src/shisad/` passed: `Success: no issues found in 218 source files`.
- First-principles behavioral gate:
  `uv run pytest tests/behavioral/test_first_principles_gates.py -q`
  passed: `6 passed`.
- Focused behavioral browser/tool follow-up:
  `uv run pytest tests/behavioral/test_behavioral_contract.py::test_contract_browser_navigate_executes_and_returns_page tests/behavioral/test_command_chat_pending_actions.py::test_command_chat_explicit_resolution_uses_planner_action_resolve -q`
  passed: `6 passed`.
- Full behavioral suite:
  `uv run pytest tests/behavioral/ -q`
  passed: `254 passed, 14 skipped`.
- Live runner verification:
  `RUNNER_INHERIT_SHISAD_ENV=1 RUNNER_TMUX_SOCKET_NAME=shisad-dev-browser-gate RUNNER_TMUX_SESSION_NAME=shisad-dev-browser-gate SHISAD_DATA_DIR=/tmp/shisad-browser-gate-data SHISAD_SOCKET_PATH=/tmp/shisad-browser-gate.sock SHISAD_POLICY_PATH=/tmp/shisad-browser-gate-policy.yaml bash runner/harness.sh start --no-debug`
  passed: daemon started on `/tmp/shisad-browser-gate.sock`.
- Live runner status:
  `RUNNER_INHERIT_SHISAD_ENV=1 RUNNER_TMUX_SOCKET_NAME=shisad-dev-browser-gate RUNNER_TMUX_SESSION_NAME=shisad-dev-browser-gate SHISAD_DATA_DIR=/tmp/shisad-browser-gate-data SHISAD_SOCKET_PATH=/tmp/shisad-browser-gate.sock SHISAD_POLICY_PATH=/tmp/shisad-browser-gate-policy.yaml bash runner/harness.sh shisad status`
  passed and reported `executors.browser.runtime.status: misconfigured`,
  `browser_command_protocol_incompatible`, `executors.browser.tools_available: false`,
  and no `browser.*` entries in `tools_registered`.
- Live runner cleanup:
  `RUNNER_INHERIT_SHISAD_ENV=1 RUNNER_TMUX_SOCKET_NAME=shisad-dev-browser-gate RUNNER_TMUX_SESSION_NAME=shisad-dev-browser-gate SHISAD_DATA_DIR=/tmp/shisad-browser-gate-data SHISAD_SOCKET_PATH=/tmp/shisad-browser-gate.sock SHISAD_POLICY_PATH=/tmp/shisad-browser-gate-policy.yaml bash runner/harness.sh stop`
  passed: daemon stop requested.
- CI follow-up, daemon site guard:
  `uv run python scripts/test_daemon_site_guard.py --baseline tests/fixtures/daemon_site_baseline.json --tests-root tests`
  initially failed because the new regression added a direct `DaemonServices.build`
  call site in `tests/unit/test_daemon_services.py` (`28 > baseline 27`);
  after routing the browser registry tests through a shared helper it passed:
  `DaemonServices.build: 45`, `run_daemon: 100`.
- CI follow-up, focused browser registry regression:
  `uv run pytest tests/unit/test_daemon_services.py -k 'browser_registry_falls_back_to_web_allowlist or misconfigured_runtime_suppresses_browser_tools' -q`
  passed: `2 passed, 54 deselected`.
- CI follow-up, static checks:
  `uv run ruff check src/ tests/ scripts/` passed.
