# Browser Automation Runbook

This runbook covers the shipped shisad browser wrapper and the host
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

Configure shisad to use the shipped protocol wrapper:

```bash
export SHISAD_BROWSER_ENABLED=1
export SHISAD_BROWSER_COMMAND=/path/to/shisad/scripts/shisad-playwright-cli.mjs
export SHISAD_BROWSER_ALLOWED_DOMAINS=example.com
```

`SHISAD_BROWSER_ALLOWED_DOMAINS` and `SHISAD_WEB_ALLOWED_DOMAINS` accept CSV
or JSON-array syntax in environment variables.

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

The shipped wrapper implements:

| Subcommand | Contract |
|---|---|
| `open [url]` | Create or mark a browser session as open. |
| `goto <url>` | Navigate the current session to a URL. |
| `eval <function> [element] --filename <path>` | Write JSON metadata with `url`, `title`, and `visible_text`. |
| `snapshot [element] --filename <path>` | Write a text snapshot with element refs, labels, selectors, hrefs, and form metadata. |
| `fill <selector> <text> [--submit]` | Fill a selector and optionally submit with Enter. |
| `click <selector>` | Click a selector. |
| `screenshot [target] --filename <path>` | Write a PNG screenshot. |
| `list` | List known wrapper sessions. |
| `close` | Delete wrapper session state and browser profile data. |

The wrapper also supports `--shisad-browser-wrapper-version`; doctor uses this
sentinel to distinguish the shisad protocol from upstream Playwright.

Snapshot lines use the form:

```text
[e1] link "Continue" selector="#continue" href="/next"
[e2] field "q" selector="#search" form_action="/submitted" form_method="get"
```

The daemon treats browser page text, snapshots, and screenshots as untrusted
browser output. Web pages cannot authorize follow-on actions; browser write
actions still go through the daemon's confirmation and policy flow.

## Troubleshooting

- `browser_command_protocol_incompatible`: `SHISAD_BROWSER_COMMAND` points at
  upstream Playwright (`playwright` / `npx playwright`) or another command that
  does not accept the shisad `-s=...` protocol. Point it at
  `scripts/shisad-playwright-cli.mjs`.
- `browser_browser_not_installed`: run `npx playwright install chromium`.
- Native library errors such as `libatk-1.0.so.0: cannot open shared object
  file`: run `sudo npx playwright install-deps chromium`.
- `browser_runtime_isolation_unavailable` or sandbox setup errors: confirm
  `bubblewrap` is installed and available to the daemon.
- `browser_hardened_wildcard_scope_unsupported`: hardened isolation requires
  literal browser hosts or URLs. Use exact domains instead of wildcard
  patterns.
