# Tool Status

This file records a point-in-time snapshot of the tool surface from a local `shisad` run. Exact status depends on configuration, enabled channels, and environment. Regenerate it in your own environment with:

```bash
uv run python scripts/live_tool_matrix.py --tool-status
```

Status meanings:

- `WORKS`: available in the tested configuration
- `GATED`: available, but routed through an approval or anomaly gate in the tested configuration
- `DISABLED`: unavailable in the tested configuration because a required dependency or configuration value was missing

Current snapshot:

Note:

- `tool.web.search` is `DISABLED` in this recorded snapshot because the daemon was started without `SHISAD_WEB_SEARCH_BACKEND_URL`. In a configured environment, the backend host must also appear in `SHISAD_WEB_ALLOWED_DOMAINS` before the tool can show up as `WORKS`.
- `tool.email.search` and `tool.email.read` are `DISABLED` in this recorded snapshot because the daemon was started without `SHISAD_MSGVAULT_ENABLED=1`. In a configured environment, shisad calls local `msgvault --local` read/search commands for tool output; account-scoped reads also inspect local msgvault archive metadata. msgvault remains responsible for provider sync and provider credentials.
- When `SHISAD_MSGVAULT_ACCOUNT_ALLOWLIST` is set, `tool.email.read` resolves
  the requested msgvault id against local archive account metadata before
  calling `show-message` with the matched internal id.
- For live tool-status probes, `SHISAD_LIVE_TOOL_MATRIX_EMAIL_ACCOUNT` scopes
  `tool.email.search` and `tool.email.read` in multi-account msgvault setups.
  `tool.email.read` uses the first id returned by `tool.email.search`, or
  `SHISAD_LIVE_TOOL_MATRIX_EMAIL_MESSAGE_ID` with the optional account. If
  neither source provides a message id, the read probe is skipped as
  `email_read_probe_message_id_unconfigured`.
- `tool.evidence.read` and `tool.evidence.promote` are `DISABLED` in this recorded snapshot because the probe does not seed a current-session evidence reference. They are covered by the evidence behavioral suite.
- The note, todo, and reminder rows use direct `tool.execute` probe payloads and show the configured control-plane gate for synthetic control API calls. User-requested session flows for these tools are covered separately by behavioral tests.
- The generated snapshot below reflects the current `scripts/live_tool_matrix.py` probe surface. Browser rows are intentionally omitted from this point-in-time table even though the browser tool surface is live in `v0.6.0` M6 when `SHISAD_BROWSER_ENABLED=1` and `SHISAD_BROWSER_COMMAND` is configured.
- MCP tool rows are intentionally omitted from this static snapshot because the surface is configuration-specific and discovered at runtime. In `v0.6.5` I2, discovered MCP tools are treated as external/untrusted runtime entries and require confirmation by default unless the server name appears in `SHISAD_MCP_TRUSTED_SERVERS`.
- Browser read-mostly tools (`browser.navigate`, `browser.read_page`, `browser.screenshot`, `browser.end_session`) are designed to work without confirmation when the destination is authorized. Browser write tools (`browser.click`, `browser.type_text`) are confirmation-gated in the live runtime.
- With `SHISAD_BROWSER_REQUIRE_HARDENED_ISOLATION=1` (the default), browser scope entries must be literal hosts/URLs; wildcard browser allowlist patterns are rejected fail-closed because the hardened connect-path layer cannot enforce wildcard sibling hosts safely.
- The browser rows remain live in the current `v0.6.x` line even though this point-in-time table intentionally omits them.

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
| tool.web.search | DISABLED | web_search_backend_unconfigured |
| tool.web.fetch | WORKS | ok |
| tool.email.search | DISABLED | msgvault_disabled |
| tool.email.read | DISABLED | msgvault_disabled |
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
- `GATED`: 10
- `DISABLED`: 6
- `FAIL`: 0
- `TOTAL`: 30
