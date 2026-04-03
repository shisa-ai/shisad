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
- The generated snapshot below reflects the current `scripts/live_tool_matrix.py` probe surface. Browser rows are intentionally omitted from this point-in-time table even though the browser tool surface is live in `v0.6.0` M6 when `SHISAD_BROWSER_ENABLED=1` and `SHISAD_BROWSER_COMMAND` is configured.
- Browser read-mostly tools (`browser.navigate`, `browser.read_page`, `browser.screenshot`, `browser.end_session`) are designed to work without confirmation when the destination is authorized. Browser write tools (`browser.click`, `browser.type_text`) are confirmation-gated in the live runtime.
- With `SHISAD_BROWSER_REQUIRE_HARDENED_ISOLATION=1` (the default), browser scope entries must be literal hosts/URLs; wildcard browser allowlist patterns are rejected fail-closed because the hardened connect-path layer cannot enforce wildcard sibling hosts safely.

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
| tool.fs.list | WORKS | ok |
| tool.fs.read | WORKS | ok |
| tool.fs.write | WORKS | ok |
| tool.git.status | WORKS | ok |
| tool.git.diff | WORKS | ok |
| tool.git.log | WORKS | ok |
| tool.message.send | DISABLED | no_delivery_channels_configured |
| tool.report_anomaly | GATED | consensus:veto:BehavioralSequenceAnalyzer |

Summary:

- `WORKS`: 14
- `GATED`: 2
- `DISABLED`: 2
- `FAIL`: 0
- `TOTAL`: 18
