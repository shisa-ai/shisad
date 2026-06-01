# Browser Automation Runbook

This runbook covers the source-checkout shisad browser wrapper and the host
prerequisites for `browser.navigate`, `browser.read_page`,
`browser.screenshot`, `browser.click`, `browser.type_text`, and
`browser.end_session`.

## Setup

Install the host sandbox and Playwright runtime prerequisites:

```bash
sudo apt-get update
sudo apt-get install -y bubblewrap nodejs npm
cd /path/to/shisad
npm install @playwright/test
npx playwright install chromium
sudo npx playwright install-deps chromium
```

`npx playwright install chromium` installs the browser binary.
`npx playwright install-deps chromium` installs the native shared libraries
Chromium needs at runtime. Both are required on a minimal Ubuntu host.

Configure shisad to use the protocol wrapper from a source checkout:

```bash
export SHISAD_BROWSER_ENABLED=1
export SHISAD_BROWSER_COMMAND=/path/to/shisad/scripts/shisad-playwright-cli.mjs
export SHISAD_BROWSER_ALLOWED_DOMAINS=example.com
```

The current PyPI wheel does not install `scripts/shisad-playwright-cli.mjs`.
Browser automation from a package install therefore requires either a source
checkout path for `SHISAD_BROWSER_COMMAND` or an operator-supplied compatible
wrapper that implements the protocol below.

`SHISAD_BROWSER_ALLOWED_DOMAINS` and `SHISAD_WEB_ALLOWED_DOMAINS` accept CSV
or JSON-array syntax in environment variables. Use the comma-separated form in
`runtime.env` or other env files for readability. If you use JSON-array syntax
in a shell-sourced env file, quote the whole value so the inner quotes are
preserved, for example `SHISAD_BROWSER_ALLOWED_DOMAINS='["example.com"]'`.

Check the configuration before the first browser turn:

```bash
uv run shisad doctor check --component browser
```

The real upstream Playwright CLI is not a valid `SHISAD_BROWSER_COMMAND`.
`shisad doctor check --component browser` reports
`browser_command_protocol_incompatible` when the command does not implement
the shisad wrapper protocol.

## Wrapper Protocol

The daemon invokes `SHISAD_BROWSER_COMMAND` with a session selector followed by
a subcommand:

```text
<command> -s=shisad-<session-id> <subcommand> [args]
```

The source-checkout wrapper implements:

| Subcommand | Contract |
|---|---|
| `open [url]` | Create or mark a browser session as open. |
| `goto <url>` | Navigate the current session to a URL. |
| `eval <function> [element] --filename <path>` | Write JSON metadata with `url`, `title`, and `visible_text`. |
| `snapshot [element] --filename <path>` | Write a text snapshot with element refs, labels, selectors, hrefs, control types, and submit-capable form metadata. |
| `fill <selector> <text> [--submit] [--click <selector>] [--no-store]` | Fill a selector, optionally submit with Enter or click a selector in the same action, and optionally skip replay-state persistence. |
| `click <selector>` | Click a selector. |
| `screenshot [target] --filename <path>` | Write a PNG screenshot. |
| `list` | List known wrapper sessions. |
| `close` | Delete wrapper session state and browser profile data. |

The daemon emits `--no-store` for `browser.type_text` calls marked
`is_sensitive=true`. A compliant wrapper must fill the value for the current
action, but must not persist or replay that value in wrapper-managed field
state. When a sensitive fill must be followed by a click, the daemon emits
`--click <selector>` so the value and click happen in one wrapper action.

The wrapper also supports `--shisad-browser-wrapper-version` and
`--shisad-browser-wrapper-doctor`; doctor uses these probes to distinguish the
shisad protocol from upstream Playwright and verify that `@playwright/test`
can be loaded.

Snapshot lines use the form:

```text
[e1] link "Continue" selector="#continue" href="/next"
[e2] field "q" selector="#search" control_type="text" form_action="/submitted" form_method="get"
```

The daemon treats browser page text, snapshots, and screenshots as untrusted
browser output. Web pages cannot authorize follow-on actions; browser write
actions still go through the daemon's confirmation and policy flow.

## Troubleshooting

- `browser_command_protocol_incompatible`: `SHISAD_BROWSER_COMMAND` points at
  upstream Playwright (`playwright` / `npx playwright`) or another command that
  does not accept the shisad `-s=...` protocol. From a source checkout, point
  it at `scripts/shisad-playwright-cli.mjs`; from a package install, point it
  at an operator-supplied compatible wrapper.
- `browser_dependency_unavailable`: the wrapper is present but cannot load its
  Node/Playwright dependency. Run `npm install @playwright/test` from the
  checkout containing `scripts/shisad-playwright-cli.mjs`.
- `browser_browser_not_installed`: run `npx playwright install chromium`.
- `browser_cache_not_writable`: make the Playwright browser cache directory
  writable by the daemon user, or set `PLAYWRIGHT_BROWSERS_PATH` to a writable
  cache directory. `PLAYWRIGHT_BROWSERS_PATH=0` uses Playwright's package-local
  browser lookup.
- Native library errors such as `libatk-1.0.so.0: cannot open shared object
  file`: run `sudo npx playwright install-deps chromium`.
- `browser_runtime_isolation_unavailable` or sandbox setup errors: confirm
  `bubblewrap` is installed and available to the daemon.
- `browser_hardened_wildcard_scope_unsupported`: hardened isolation requires
  literal browser hosts or URLs. Use exact domains instead of wildcard
  patterns.
