# Tool Status

This file records a point-in-time snapshot of the tool surface from a local `shisad` run. Exact status depends on configuration, enabled channels, and environment. Regenerate it in your own environment with:

```bash
uv run --frozen python scripts/live_tool_matrix.py --tool-status
```

Status meanings:

- `WORKS`: available in the tested configuration
- `GATED`: available, but routed through an approval or anomaly gate in the tested configuration
- `DISABLED`: unavailable in the tested configuration because a required dependency or configuration value was missing
- `BROKEN`: the probe could not exercise an expected tool path; release snapshots
  must record zero broken rows

Current snapshot:

This snapshot was generated on 2026-07-22 from public development ref
`d4d2f465d96ed93ac51a9cfbe2569d043b17747f` in an isolated data directory.
The remote planner route was configured and responsive; external channels,
browser, MsgVault, RealityCheck, and web search were explicitly disabled. The
filesystem root was the source checkout. The direct-RPC probe is deliberately
fast; later safe tools can therefore appear as `GATED` when the behavioral
sequence control sees the synthetic burst.

This host had no available `nsjail` or container sandbox backend. Under the
default `supported` profile, sandbox doctor correctly reported `blocked` and
the three command-backed probe rows failed closed with
`degraded_enforcement`. To record tool functionality separately from host
containment availability, the table below was generated with the explicit
`expert_host_fallback` policy posture. Sandbox doctor reported `degraded` with
`expert_host_fallback_enabled`; the `WORKS` command rows therefore make **no
supported-isolation claim**. A supported deployment must keep the default
profile and provide the required backend instead.

Note:

- The `v0.8.1` `assistant` package extra installs Textual plus MCP and the four
  channel client families. Installation alone does not enable a channel,
  authenticate a remote service, or turn a configuration-gated row into
  `WORKS`; the snapshot remains environment-specific.
- The v0.8.1 config/help/UI commands do not add or enable assistant tools, so
  they do not change the generated rows below. `shisad init`, config/env
  inspection, built-in theme/accessibility controls, and the local static
  `web-ui` export are operator CLI surfaces. `doctor` remains read-only, custom
  theme-file selection remains unsupported, and the static export is not a
  live operator web application.
- The local Linux/amd64 container candidate includes `bwrap`, `pasta`,
  `iptables`, and `nsenter`, but the Docker host decides whether nested
  namespaces are usable. Before daemon startup, the non-root entrypoint probes
  the runtime namespace flags and a real pasta attachment; all bwrap-backed
  doctor rows stay unavailable unless that probe succeeds. Its fixed non-root
  posture does not claim `CAP_NET_ADMIN`, so the current connect-path diagnostic
  reports unavailable. An unavailable boundary remains an actionable
  fail-closed `supported` result, never an automatic `expert_host_fallback`
  selection.
- Browser and search services are not bundled into either artifact profile.
  Browser rows still require an operator-supplied compatible wrapper/runtime,
  and `tool.web.search` still requires a configured SearxNG-compatible
  endpoint.
- `tool.web.search` is `DISABLED` in this recorded snapshot because
  `SHISAD_WEB_SEARCH_ENABLED=false` was selected. Enabling it also requires a
  configured SearxNG-compatible backend. In a configured environment,
  IP-literal, `localhost`, and `.local` / `.internal` / `.lan` backend hosts
  must appear in the effective web allowlist before the tool can show up as
  `WORKS`; set `SHISAD_WEB_ALLOWED_DOMAINS` for runner/env-file setups, or rely
  on policy egress hosts when that variable is unset. Public backend hosts do
  not need an allowlist entry just to run `web.search`.
- `tool.email.search` and `tool.email.read` are `DISABLED` in this recorded snapshot because the daemon was started without `SHISAD_MSGVAULT_ENABLED=1`. In a configured environment, shisad calls local `msgvault --local` read/search commands for tool output; reads also inspect local msgvault archive email metadata. msgvault remains responsible for provider sync and provider credentials.
- `tool.email.read` resolves the requested msgvault id against local archive
  email metadata before calling `show-message` with the matched internal id;
  when `SHISAD_MSGVAULT_ACCOUNT_ALLOWLIST` is set, that metadata lookup is also
  account-scoped.
- For live tool-status probes, `SHISAD_LIVE_TOOL_MATRIX_EMAIL_ACCOUNT` scopes
  `tool.email.search` and `tool.email.read` in multi-account msgvault setups.
  `tool.email.read` uses the first id returned by `tool.email.search`, or
  `SHISAD_LIVE_TOOL_MATRIX_EMAIL_MESSAGE_ID` with the optional account. If
  neither source provides a message id, the read probe is skipped as
  `email_read_probe_message_id_unconfigured`.
- `tool.evidence.read` and `tool.evidence.promote` are `DISABLED` in this recorded snapshot because the probe does not seed a current-session evidence reference. They are covered by the evidence behavioral suite.
- `tool.time.now` is a planner-visible structured clock tool for current
  date/time answers. It has no external dependency. The direct-RPC snapshot
  exercises it; in this run the synthetic probe burst reached the behavioral
  sequence gate, so the row is `GATED`. Session-message behavioral tests cover
  the normal current-time journey independently.
- `tool.attachment.ingest` is the local attachment MVP. It reads allowlisted
  local paths only, returns tainted ArtifactLedger manifest refs, and stores
  unsupported, malformed, oversized, or transcript-risky media as quarantined
  manifests that are not readable through the default evidence read/promote
  path.
- The file.read, attachment, note, todo, and reminder rows use direct `tool.execute` probe payloads and show the configured control-plane gate for synthetic control API calls. User-requested session flows for these tools are covered separately by behavioral tests.
- The four network channel adapters do not currently advertise a common
  provider idempotency or automatic-delivery-recovery capability. Their
  durable delivery ledger preserves attempt/outcome evidence and prevents
  silent local replay; it does not create a provider exactly-once guarantee.
  `tool.message.send` is disabled in this snapshot because no channel was
  configured, so this direct table is not delivery-recovery evidence.
- Pending-action restart recovery is separately restricted to trusted
  persisted retry descriptors. Target-bearing or otherwise ambiguous attempts
  become `outcome_unknown`; the live tool matrix does not simulate a crash and
  is not evidence of arbitrary effect retry safety.
- Assistant `fs.*` and `git.*` tools reject the daemon-managed data root and
  exact configured external approval, signer, and operator `SOUL.md` control
  files (including adjacent lock files). Unrelated paths under configured
  filesystem roots remain available. `shisad doctor check --component storage`
  reports redacted lock and finite-store health separately from this tool
  snapshot.
- Assistant `git.status`, `git.diff`, and `git.log` run with bounded Git
  environment/config controls. Repository fsmonitor, external diff/textconv,
  signature-verifier, pager, and ambient helper settings do not execute on
  these read paths. Ordinary status/diff/log output remains available;
  `git.status` and `git.diff` instead return an actionable block when an active
  checkout filter is both executable and required. Commit-only `git.log`
  remains available in that case.
- Thread control tools (`thread.list`, `thread.inspect`, `thread.resume`,
  `thread.close`, and `thread.why`) are live control/API surfaces, but this
  static snapshot omits them until the live probe seeds an `open_thread`
  fixture. Their user-visible contract is covered by behavioral tests.
- `tool.action.resolve` is omitted until the live probe seeds a pending action
  bound to the probe's current trusted turn. Its confirmation/rejection contract
  is covered by command-chat behavioral tests.
- Timeline tools (`memory.timeline.search`, `memory.timeline.read`, and
  `memory.timeline.promote`) are live control/API and CLI surfaces in the
  v0.7.3 line, but this static snapshot omits them until the live probe seeds a
  prior transcript/timeline-handle fixture and a promotable read packet. Their
  user-visible search/read/promote contract is covered by behavioral tests.
- The generated snapshot below reflects the current `scripts/live_tool_matrix.py` probe surface. Browser rows are intentionally omitted from this point-in-time table even though the browser tool surface is live in `v0.6.0` M6 when `SHISAD_BROWSER_ENABLED=1` and `SHISAD_BROWSER_COMMAND` is configured.
- MCP tool rows are intentionally omitted from this static snapshot because the surface is configuration-specific and discovered at runtime. In `v0.6.5` I2, discovered MCP tools are treated as external/untrusted runtime entries and require confirmation by default unless the server name appears in `SHISAD_MCP_TRUSTED_SERVERS`.
- Browser read-mostly tools (`browser.navigate`, `browser.read_page`, `browser.screenshot`, `browser.end_session`) are designed to work without confirmation when the destination is authorized. Browser write tools (`browser.click`, `browser.type_text`) are confirmation-gated in the live runtime. The source-checkout wrapper and host setup steps are documented in `docs/runbooks/BROWSER.md`; `SHISAD_BROWSER_COMMAND` must point at the shisad wrapper protocol, not upstream Playwright. The current PyPI wheel does not install the Node wrapper, so package installs need an explicit compatible wrapper path.
- With `SHISAD_BROWSER_REQUIRE_HARDENED_ISOLATION=1` (the default), browser scope entries must be literal hosts/URLs; wildcard browser allowlist patterns are rejected fail-closed because the hardened connect-path layer cannot enforce wildcard sibling hosts safely.
- The browser rows remain live in the published `v0.7.x` line even though this point-in-time table intentionally omits them.
- `tool.lockdown.resume` is a planner-driven structured control tool exposed only
  to trusted command-chat sessions at `caution` lockdown level. It records the
  audit actor chain `human_confirmation -> planner_lockdown_resume`. The static
  snapshot omits it until the probe creates a bounded caution-level fixture;
  lockdown behavioral tests cover the stateful journey.
- Command-backed tool rows assume a usable configured isolation backend under
  the default `supported` containment profile. Without one, those rows fail
  closed and doctor reports the missing backend. The explicit
  `expert_host_fallback` profile can preserve command functionality on the
  host, with persistent warnings and truthful requested/actual backend data;
  that posture is not a supported-isolation result.
- Network-enabled command rows additionally require Linux `bwrap`, `pasta`,
  and connect-path enforcement. The command is released inside its isolated
  IPv4 network namespace, with Linux capabilities dropped, only after
  destination rules are installed.
  Pre-authorized hostnames are pinned without external DNS or port forwarding.
  Doctor backend rows expose `network_namespace_available`,
  `network_available`, and `dns_control_available`; missing network components
  fail closed under `supported` and may use the host only under the explicit
  `expert_host_fallback` posture.
- `shisad memory benchmark` and `shisad memory sut` are CLI evaluation
  surfaces, not live assistant tools, so they are intentionally omitted from
  this tool table. See `docs/memory-evals.md` for memory evaluation commands.

| Tool | Status | Detail |
|------|--------|--------|
| prompt.1 | WORKS | response_ok |
| prompt.2 | WORKS | response_ok |
| prompt.3 | WORKS | response_ok |
| tool.retrieve_rag | WORKS | allowed |
| tool.shell.exec | WORKS | allowed |
| tool.http.request | WORKS | allowed |
| tool.file.read | WORKS | allowed |
| tool.file.write | GATED | consensus:veto:BehavioralSequenceAnalyzer |
| tool.web.search | DISABLED | web_search_disabled |
| tool.web.fetch | WORKS | ok |
| tool.time.now | GATED | consensus:veto:BehavioralSequenceAnalyzer |
| tool.email.search | DISABLED | msgvault_disabled |
| tool.email.read | DISABLED | msgvault_disabled |
| tool.attachment.ingest | GATED | consensus:veto:BehavioralSequenceAnalyzer |
| tool.fs.list | WORKS | ok |
| tool.fs.read | WORKS | ok |
| tool.fs.write | WORKS | ok |
| tool.git.status | WORKS | ok |
| tool.git.diff | WORKS | ok |
| tool.git.log | WORKS | ok |
| tool.note.create | GATED | consensus:veto:BehavioralSequenceAnalyzer |
| tool.note.list | GATED | consensus:veto:BehavioralSequenceAnalyzer |
| tool.note.search | GATED | consensus:veto:BehavioralSequenceAnalyzer |
| tool.todo.create | GATED | consensus:veto:BehavioralSequenceAnalyzer |
| tool.todo.list | GATED | consensus:veto:BehavioralSequenceAnalyzer |
| tool.todo.complete | GATED | consensus:veto:BehavioralSequenceAnalyzer |
| tool.reminder.create | GATED | consensus:veto:BehavioralSequenceAnalyzer |
| tool.reminder.list | GATED | consensus:veto:BehavioralSequenceAnalyzer |
| tool.message.send | DISABLED | no_delivery_channels_configured |
| tool.evidence.read | DISABLED | no_evidence_ref_available |
| tool.evidence.promote | DISABLED | no_evidence_ref_available |
| tool.report_anomaly | GATED | consensus:veto:BehavioralSequenceAnalyzer |

Summary:

- `WORKS`: 14
- `GATED`: 12
- `DISABLED`: 6
- `BROKEN`: 0
- `TOTAL`: 32
