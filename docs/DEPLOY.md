# Deploy and Run

Users and agents looking to set up shisad on their own system should start here.

shisad is a long-running daemon — it is designed to run on a dedicated instance or
container, not inside your development environment. We recommend a standalone VM
(cloud instance or local VM) or container as the deployment target.

## One-Click Instance Deployment

Coming soon. For now, follow the manual paths below.

---

## Package Installation (v0.8.1+)

The supported consumer profile is the `assistant` extra:

```bash
uv tool install 'shisad[assistant]'
shisad --help
shisad doctor check --component all
```

It installs the Textual UI plus MCP, Matrix E2EE, Discord, Telegram, and Slack
client libraries. It does not enable any channel or supply credentials.
PromptGuard remains a separate optional model runtime; combine it explicitly
as `shisad[assistant,promptguard]` when wanted. The latest currently published
package is `v0.8.0`, so the `assistant` PyPI command applies after `v0.8.1` is
published or to an equivalent wheel built from this tree.

The smaller base package still provides `shisad --help`; `shisad[chat]`
remains available for a Textual-only installation. Missing optional surfaces
fail with an install/configuration action rather than requiring the repository
on `PYTHONPATH`.

## Local Container Candidate (v0.8.1)

The repository Dockerfile is a tested Linux/amd64 release candidate, not a
published or signed registry image. Build it locally from a reviewed checkout:

```bash
git clone https://github.com/shisa-ai/shisad.git
cd shisad
docker build --tag shisad:local .
docker volume create shisad-data
docker volume create shisad-workspace
```

Create an operator policy and an env file outside the image, then start the
fixed non-root uid/gid `10001` runtime:

```bash
docker run --detach --name shisad \
  --mount source=shisad-data,target=/var/lib/shisad \
  --mount source=shisad-workspace,target=/workspace \
  --mount type=bind,src=/absolute/path/policy.yaml,dst=/etc/shisad/policy.yaml,readonly \
  --env-file /absolute/path/runtime.env \
  shisad:local

docker exec shisad shisad status
docker exec shisad shisad doctor check --component sandbox
```

The image launches the installed wheel through Tini, uses the real daemon
status command for health, and keeps `/var/lib/shisad` and `/workspace` on
separate volumes. `docker stop shisad && docker rm shisad` does not remove
those named volumes. Delete them only as a separate, intentional data-removal
operation.

The image contains `bwrap`, `pasta`, `iptables`, and `nsenter`, but nested
namespace availability is controlled by the Docker host. The fixed non-root
entrypoint first exercises the namespace flags used by the runtime and attaches
pasta to a disposable isolated network namespace. Only a successful probe is
cached in the owner-only runtime directory and exposed through the bwrap-backed
doctor rows. The candidate does not claim `CAP_NET_ADMIN`, so its connect-path
diagnostic is unavailable by default. Always inspect the sandbox doctor result
on the target host. If a required boundary is unavailable, the default
`supported` profile reports the missing component and command-backed operations
that require it fail closed; the image never selects `expert_host_fallback`
automatically. Do not use `--privileged` merely to turn that diagnostic green.
Bind-mounted data/workspace directories, if used in place of named volumes,
must be owned and writable by uid/gid `10001`.

Browser automation and web search are not bundled services. Browser use still
needs an explicit compatible wrapper plus browser runtime, and web search
still needs an explicit SearxNG-compatible backend; see the respective setup
sections below.

## Development Source Checkout

The remaining `uv run ...` examples in this guide describe a source checkout.
With a package install, omit `uv run`; inside the local container, prefix the
same CLI with `docker exec shisad`.

- A dedicated Linux host (VM, cloud instance, or container)
- Python 3.12+
- [uv](https://docs.astral.sh/uv/)
- repo checked out locally

Host bootstrap (Ubuntu 24.04 example):

```bash
sudo apt-get update
sudo apt-get install -y git curl build-essential python3.12 python3.12-venv
curl -LsSf https://astral.sh/uv/install.sh | sh
export PATH="$HOME/.local/bin:$PATH"
```

Install dependencies:

```bash
git clone https://github.com/shisa-ai/shisad.git
cd shisad
uv --no-config sync --frozen --group dev --group channels-runtime
```

This creates and uses the repo `.venv`. `--no-config --frozen` consumes the
repository's reviewed lock instead of silently replacing it with discovered
user/system uv config. Explicit `UV_*` environment variables and command-line
overrides remain caller-owned and should be cleared when they conflict with
this setup path. An environment that intentionally applies a different
package-age cutoff must admit every security floor in `pyproject.toml`; do not
lower those floors or narrow supported Python versions to make a stale package
universe resolve.

To install this checkout into an already-active conda/mamba env instead:

```bash
mamba install -y -c conda-forge uv
uv export --frozen --format requirements.txt --group dev \
  --group channels-runtime \
  --output-file /tmp/shisad-requirements.txt
uv pip install --python "$CONDA_PREFIX/bin/python" \
  -r /tmp/shisad-requirements.txt --strict
uv pip install --python "$CONDA_PREFIX/bin/python" -e .
```

YARA-backed content scanning is included in the base install through
`textguard[yara]`. If you want local PromptGuard runtime checks in the daemon
from a source checkout, include the security runtime dependency group:

```bash
uv --no-config sync --frozen --group security-runtime --group dev --group channels-runtime
```

For package installs, use the first-class PromptGuard extra, for example
`uv pip install 'shisad[promptguard]'`. `security-runtime`,
`security-build`, `interop`, `channels-runtime`, and `coverage` are uv
dependency groups from `[dependency-groups]`; install them with `--group` in a
source checkout. The complete package profile is `shisad[assistant]`; the
smaller `chat` and separate `promptguard` profiles remain available for
specialized installs.

Optional groups:

```bash
uv --no-config sync --frozen --group security-runtime    # Local ONNX PromptGuard checks
uv --no-config sync --frozen --group security-build      # Model-pack build tooling
uv --no-config sync --frozen --group interop             # MCP client runtime
uv --no-config sync --frozen --group channels-runtime    # Matrix/Discord/Telegram/Slack
uv --no-config sync --frozen --group coverage            # pytest-cov
```

`security-build` is only needed for PromptGuard model export/download/build
workflows. It is heavier than `security-runtime` and includes PyTorch. Daemon
operation with `security-runtime` alone should have PromptGuard's
`onnxruntime` and `transformers` dependencies available through
`textguard[promptguard]`, but not `torch`; if Transformers logs "PyTorch was
not found" during startup in that profile, that warning is expected and does
not mean the daemon runtime group was installed incorrectly.

`interop` installs the MCP client dependency. Configure MCP servers via
`SHISAD_MCP_SERVERS` (JSON) or `DaemonConfig.mcp_servers`; discovered tools
register under runtime ids like `mcp.<server>.<tool>`. MCP tools require
confirmation by default unless the server name appears in
`SHISAD_MCP_TRUSTED_SERVERS`, and stdio servers receive a sanitized
subprocess environment plus any explicit `env` overrides you configure per
server.

A2A ingress is included in the base install; no extra dependency group is
required. Configure it via `SHISAD_A2A` (JSON) or `DaemonConfig.a2a`. The A2A
surface is signed inbound ingress over direct socket or HTTP transports, with
fail-closed `allowed_intents` grants, per-fingerprint sliding-window rate
limits, and `A2aIngressEvaluated` audit events for success and rejection
outcomes.

Generate the local daemon identity first:

```bash
uv run shisad a2a keygen \
  --private-key "$HOME/.config/shisad/a2a/private.key" \
  --public-key "$HOME/.config/shisad/a2a/public.key"
```

Example `SHISAD_A2A` payload:

```bash
export SHISAD_A2A='{
  "enabled": true,
  "identity": {
    "agent_id": "local-agent",
    "private_key_path": "/home/ubuntu/.config/shisad/a2a/private.key",
    "public_key_path": "/home/ubuntu/.config/shisad/a2a/public.key"
  },
  "listen": {
    "transport": "socket",
    "host": "127.0.0.1",
    "port": 9820
  },
  "agents": [
    {
      "agent_id": "remote-agent",
      "fingerprint": "sha256:<remote-public-key-fingerprint>",
      "public_key_path": "/home/ubuntu/.config/shisad/a2a/remote-agent.pub",
      "address": "127.0.0.1:9820",
      "transport": "socket",
      "trust_level": "untrusted",
      "allowed_intents": ["query"]
    }
  ],
  "rate_limits": {
    "max_per_minute": 60,
    "max_per_hour": 600
  }
}'
```

Operator notes:

- `allowed_intents` is fail-closed. If you omit it for a configured remote
  agent, that agent's inbound A2A requests are rejected until you add explicit
  grants.
- Each configured remote agent must have a unique verified public-key
  fingerprint. Shared-key aliases are rejected at config load so grants and
  rate limits stay anchored to one authenticated remote principal.
- Socket peers use `address: "host:port"` with `transport: "socket"`. HTTP
  peers use full `http(s)://...` URLs with `transport: "http"`.
- Each accepted or rejected inbound request emits an `A2aIngressEvaluated`
  audit event with sender identity, intent, outcome, and rejection reason when
  applicable.

## Preflight Checklist

Before starting the daemon:

- [ ] Python 3.12+ and `uv` installed
- [ ] At least one LLM provider credential available (see provider table below)
- [ ] Data directory writable (default: `~/.local/share/shisad`)
- [ ] Socket path writable (default: `$XDG_RUNTIME_DIR/shisad/control.sock`
      when `XDG_RUNTIME_DIR` is an absolute path, otherwise
      `/tmp/shisad-<uid>/control.sock`)
- [ ] Optional: at least one channel credential (Discord, Telegram, Slack, or Matrix)
- [ ] Optional: policy file created (`runner/policy.default.yaml` is a starting point)

## Data-Root Ownership and State Recovery

### Operator-config migration

The current operator TOML schema is `1`. Inspect an existing config without
writing it:

```bash
shisad --config /absolute/path/config.toml config upgrade
```

A legacy file with no `schema_version` has one known non-breaking migration.
Persist it explicitly with `config upgrade --write`. Before replacement,
shisad creates an exact `config.toml.pre-v1.bak`, validates the candidate, and
uses same-directory atomic replacement. On POSIX it enforces owner-only mode
and parent-directory synchronization; on other supported platforms the write
summary reports unavailable capabilities instead of overstating them. Stop
shisad before manually restoring that backup, restore it only to its original
config path, then run `config validate`.

Interactive unmanaged startup may persist this safe migration and reports the
backup. Managed or non-interactive startup does not infer write permission: it
uses the compatible values in memory, reports that persistence is pending, and
names the explicit command. Schema versions newer than `1`, malformed values,
and explicit older values are refused without mutation or downgrade. This is
operator-config recovery only; it is not a data-root backup or package
rollback claim.

For an env-only deployment that is moving selected non-secret settings into a
file, use `shisad --config PATH init --from-env`. The generated file uses
owner-only mode on POSIX and reports when equivalent permission tightening is
unavailable. It contains only typed, non-default fields sourced from supported
environment variables. Raw API keys, bot tokens, credentials, nested
secret-bearing objects, and other secret fields are omitted and remain
environment-owned.

Only one daemon may own a given `SHISAD_DATA_DIR` at a time. Ownership is
acquired before stores or control endpoints are opened; a same-root contender
fails with an actionable error without altering feature state. Separate data
roots with separate endpoints can run concurrently.

### SQLite schema migration

The replay and delivery databases use strict schema version `1` admission.
The shared memory and timeline databases also use schema version `1`; when
startup finds a structurally recognized legacy version-0 database, it creates
and validates an exact `<database>.pre-v1.bak` before applying the ordered
migration in one native SQLite transaction. Durable rows are preserved. A
failed migration leaves the version-0 database and rollback copy intact so a
later startup can retry against the same bytes.

Startup refuses an empty existing database, an unrecognized or corrupt schema,
a version newer than this build supports, an unsafe database or backup path, a
mismatched pre-existing backup, or a backup whose database is missing. It does
not downgrade or reset uncertain state. Stop the daemon before inspecting or
restoring a rollback copy, preserve the refused files, and restore the backup
only to its matching database path. The migration copy protects one physical
database at one schema boundary; it is not a complete data-root backup.

FTS and fallback lexical indexes in the memory database are derived,
capability-selected search state. Their presence does not define a separate
physical schema version. See [the SQLite runbook](runbooks/SQLITE.md) for
inspection and recovery details.

On supported hard-lock platforms, `.shisad.lock` is intentionally persistent.
Its presence alone does not mean a daemon is running—the library-managed lock
held by the live process is authoritative. Daemon startup, backup, and restore
all open this same regular child relative to a pinned data-root handle and
verify that the locked descriptor has that child's identity. Check the daemon
and finite-store posture with:

```bash
shisad doctor check --component storage
```

Small included state stores use checksummed envelopes and atomic replacement.
If doctor reports `corrupt` or `unsupported`, that component is blocked while
conversation and unrelated features remain available. Existing bytes are
preserved. Restore a known-good backup or use the component's documented
explicit reset/re-enrollment path; shisad does not automatically repair,
quarantine, or replace uncertain state.

Atomic replacement, parent-directory sync, and permission tightening are
reported according to the host and filesystem. They are not a universal
power-loss guarantee. The lock is local to one host and is not suitable for a
shared multi-host data root or active/active deployment.

### Backup, upgrade, and uninstall boundaries

- **Backup:** stop the daemon that owns the data root, verify it is stopped,
  and create a manifest-verified backup without overwriting an existing
  artifact:

  ```bash
  shisad data backup /operator-controlled/shisad-2026-08-20.shisad-backup
  ```

  The command uses the configured `SHISAD_DATA_DIR`, refuses a held daemon
  lock, symlinks, and special files, and includes every safe directory and
  regular file except the root `.shisad.lock`. The single-file archive is
  owner-only where supported but is **not encrypted**; keep it in
  operator-controlled storage. Preserve the operator TOML, policy, environment
  secrets, external signer/helper configuration, external msgvault roots, and
  assistant workspace separately because they may live outside the data root.
  Per-database pre-migration copies do not replace this full-root backup.
  Source traversal keeps each directory open while enumerating and opening its
  direct children, and archive publication is relative to an already-open
  destination parent. Windows enumerates the opened directory handle rather
  than reconstructing a pathname. If the host cannot provide these native
  rooted operations, backup refuses instead of using a check-then-open pathname
  fallback. On POSIX, an interrupted failure may retain a disclosed temporary
  or published artifact in the destination directory: preserve the reported
  residue, inspect it manually, and remove it only after identifying the exact
  object. This avoids deleting a concurrently substituted name.
- **Restore:** keep the existing root intact, stop shisad, and restore only into
  an absent or empty explicitly named destination:

  ```bash
  shisad data restore /operator-controlled/shisad-2026-08-20.shisad-backup \
    --destination /absolute/path/to/restored-data
  ```

  Restore verifies the canonical manifest and every payload before writing and
  never merges with existing state. It pins the destination parent and creates
  every nested child relative to its live parent handle; Windows reparse points
  and POSIX links are refused instead of followed. Windows can remove only
  handles whose identity it created and verified after a later failure. POSIX
  cannot portably delete by verified inode, so a failure retains and reports a
  partial destination instead of risking deletion of a replacement. Preserve
  that residue for inspection or remove the exact operator-verified tree. A
  host without the required native rooted primitive refuses actionably. Point
  the selected configuration at the restored root, then run
  `shisad start`, `shisad status`, and `shisad doctor check --component all`.
  Offline verification is not a runtime health claim. To roll back, stop the
  daemon and restore a different verified backup into another absent or empty
  root; mixing individual files from different backups is unsupported.

  These rooted operations and the lifecycle lock coordinate ordinary local
  shisad processes on one host. They are not a distributed lease and do not
  claim protection from an administrator, a compromised host, or unrestricted
  malicious native code running as the same user.

- **Upgrade:** take the stopped-daemon backup first, install the reviewed wheel
  or image, and start exactly one daemon against the existing root. Run
  `shisad doctor check --component all` before enabling unattended work. An
  upgrade does not imply provider reconciliation for an existing
  `outcome_unknown` action; reconcile it using its recorded identifiers.
- **Uninstall:** removing the Python package, source checkout, container, or
  service definition does not intentionally delete the data root, workspace,
  operator config, policy, credentials, or named container volumes. Remove
  those separately only after identifying the exact paths/volumes and deciding
  that their retained state and backups are no longer needed.

## Recommended: Runner Harness

The runner harness is the default local operator path. It handles env isolation,
secret loading, policy bootstrapping, and daemon lifecycle.

Quick start:

```bash
bash runner/harness.sh start       # background; requires tmux
bash runner/harness.sh start --fg  # foreground; no tmux required
bash runner/harness.sh status
bash runner/harness.sh shisad status
bash runner/harness.sh logs --follow
```

Create a session and talk to the daemon:

```bash
sid="$(bash runner/harness.sh session new --user ops --workspace local)"
bash runner/harness.sh session say "$sid" "Say hello in one short sentence."
```

### Secrets and Overrides

- `SHISAD_ENV_FILE` can point at a system/user env file
- `runner/.env` is the repo-local override file (gitignored)
- Copy `runner/.env.example` to `runner/.env` for local-only values

Recommended env file layout for non-runner deployments:

```bash
mkdir -p ~/.config/shisad
touch ~/.config/shisad/runtime.env
chmod 600 ~/.config/shisad/runtime.env
```

Source it from your shell init (`~/.bashrc` or `~/.zshrc`):

```bash
if [ -f "$HOME/.config/shisad/runtime.env" ]; then
  set -a
  . "$HOME/.config/shisad/runtime.env"
  set +a
fi
```

When `runtime.env` is loaded through shell `source`, prefer comma-separated
values for list fields, for example `SHISAD_WEB_ALLOWED_DOMAINS=a.com,b.com`.
Quoted JSON arrays also work, for example
`SHISAD_WEB_ALLOWED_DOMAINS='["a.com","b.com"]'`, but unquoted JSON arrays lose
their inner quotes during shell parsing and arrive as invalid JSON.

### Provider Credentials

Planner preset to credential mapping:

| Preset | Required key |
| --- | --- |
| `shisa_default` | `SHISA_API_KEY` |
| `openai_default` | `OPENAI_API_KEY` |
| `openrouter_default` | `OPENROUTER_API_KEY` |
| `google_openai_default` | `GEMINI_API_KEY` |
| `vllm_local_default` | none |

See `README.md` for full provider routing examples (mixed mode, custom base URLs, auth modes).

For model routes, v0.8.2 can persist a logical credential reference instead of
a raw secret in TOML. Environment references store only the environment
variable name:

```bash
export OPENAI_API_KEY="<openai-api-key>"
uv run shisad credential set model.primary \
  --backend env --locator OPENAI_API_KEY
```

Then select the logical name in the operator config:

```toml
[model]
planner_provider_preset = "openai_default"
planner_remote_enabled = true
planner_api_key_ref = "model.primary"
```

An explicit reference suppresses ambient provider-key auto-detection for that
route. If the referenced value is unavailable, provider readiness remains
actionable while local/core daemon construction remains available. Do not set
both `planner_api_key` and `planner_api_key_ref` (or the corresponding global,
embeddings, or monitor pair).

The built-in file backend accepts values only through a hidden prompt or
`--stdin`; it stores permission-protected plaintext under the active data root
with `0700` directories and `0600` files. Install the optional maintained OS
keyring integration with `uv --no-config sync --frozen --extra credentials` (source
checkout) or `pip install 'shisad[credentials]'` (package install). A missing
or unusable keyring is reported and never falls back to the file backend.

### Health Checks

```bash
bash runner/harness.sh status
bash runner/harness.sh doctor all
```

Stop or restart:

```bash
bash runner/harness.sh stop
bash runner/harness.sh restart
```

For full runner behavior, separate instance patterns, and troubleshooting, see
`runner/RUNBOOK.md` and `runner/README.md`.

## Manual Daemon Start

If you do not want to use the runner harness, set a minimal baseline:

```bash
export SHISAD_DATA_DIR="$HOME/.local/share/shisad"
case "${XDG_RUNTIME_DIR:-}" in
  /*) export SHISAD_SOCKET_PATH="$XDG_RUNTIME_DIR/shisad/control.sock" ;;
  *) export SHISAD_SOCKET_PATH="/tmp/shisad-$(id -u)/control.sock" ;;
esac
export SHISAD_POLICY_PATH="$PWD/.local/policy.yaml"
export SHISAD_LOG_LEVEL="INFO"
```

Set provider credentials as needed:

```bash
export SHISA_API_KEY="<shisa-api-key>"
```

Start the daemon:

```bash
uv run shisad start --foreground
```

`--foreground` is the right posture for containers and service supervisors.
For an interactive POSIX install, `uv run shisad start` launches a detached
child, waits boundedly for the control API, and reports a redacted health
summary plus its owner-only log at `<data-dir>/logs/daemon.log`. A repeated
start is idempotent while that socket is reachable. Native Windows daemon
transport/background support is not claimed by this path.

In another shell:

```bash
uv run shisad status
uv run shisad doctor check --component all
uv run shisad doctor check --component storage
uv run shisad tui --plain
```

The storage doctor reports the Python `sqlite3` runtime, SQLite library
version, and FTS5 availability. FTS5 is the preferred memory retrieval path;
see [`docs/runbooks/SQLITE.md`](runbooks/SQLITE.md) if this check reports a
degraded runtime.

Create a session:

```bash
uv run shisad session create --user alice --workspace demo
uv run shisad session list
uv run shisad session message <session-id> "Say hello in one sentence."
```

---

## Channel Setup

shisad supports Discord, Telegram, Slack, and Matrix as messaging channels. Each
channel uses default-deny identity allowlisting — only explicitly allowed user IDs
can interact with the daemon.

On the v0.8.2 development tree, prefer logical channel token references over
raw `SHISAD_*_TOKEN` config values. Register each reference with
`shisad credential set` (environment, optional keyring, or owner-only local
file), then use `shisad setup channel --channel <name> ...`. The command validates and
prints a reference-only fragment but does not publish it. `--skip-probe` makes
no connector call. An optional fixed test notice requires both `--send-test`
and an explicit `--test-target`, uses the normal durable delivery path exactly
once, and does not claim an inbound round trip. If its effect is uncertain,
inspect the target before deciding whether to rerun.

Raw token settings below remain compatibility inputs, but a raw value and its
matching `*_TOKEN_REF` are mutually exclusive. Missing optional credentials or
client libraries degrade only that channel. For ingress, use the channel's
`*_TRUSTED_USERS` field (or the generic identity allowlist) explicitly;
connection or outbound delivery never grants trust.

### Durable delivery reconciliation

Every outbound channel attempt is recorded in the durable outbox. Operators
can list or inspect those records without exposing the message payload or
delivery metadata:

```bash
shisad delivery list --state outcome_unknown
shisad delivery inspect <dres-or-dly-id>
shisad delivery inspect <dres-or-dly-id> --json
```

For an uncertain provider attempt, `delivery resolve` performs a lookup only
when the active adapter declares an authoritative reconciliation contract:

```bash
shisad delivery resolve <dres-or-dly-id>
```

The command never sends the message again. A provider-confirmed delivery is
recorded with its matching receipt. Authoritative absence becomes the terminal
`reconciled_absent` state; submit a fresh request through the normal policy and
approval path if you want to retry. Unknown, failed, mismatched, or unsupported
lookups remain uncertain.

The current Matrix, Discord, Telegram, and Slack adapters do not yet expose an
authoritative reconciliation contract, so their uncertain attempts report
`unsupported` and remain `outcome_unknown`. Inspect the provider before
deciding whether to submit fresh work. This limitation also means that seeing a
provider transaction-ID feature in its API is not, by itself, a shipped restart
recovery guarantee.

For a combined setup, enroll the references first and create a bounded
secret-free selection document. For example:

```yaml
provider:
  preset: openai_default
  model_id: gpt-5.4-2026-03-05
  credential_ref: model.primary
policy:
  profile: strict
channels:
  - channel: discord
    bot_token_ref: channel.discord
    default_target: "<channel-id>"
    trusted_users: ["<your-discord-user-id>"]
```

`shisad setup wizard` provides the interactive equivalent on a real unmanaged
terminal, including zero-or-more channel selection and one final default-no
publication confirmation. Managed deployments and scripts should use:

```bash
# Dry run; resolves references but makes no network call or file write.
shisad setup apply --selection setup.yaml --skip-probes

# Explicitly publish this unverified selection.
shisad setup apply --selection setup.yaml --skip-probes --write
```

Remove `--skip-probes` to run each existing bounded provider/channel check
serially. A failed check is not retried and blocks publication. OpenRouter and
local vLLM combined selections require an explicit `model_id`. The successful
write creates `policy.yaml` before a sibling commented `config.toml`; each is
exclusive, no-overwrite, and `0600`, and only logical `*_ref` values enter the
config. The pair is not transactional. If config publication fails after the
policy file completes, the policy is inert and the error identifies it for
inspection/removal. `setup apply` never starts or restarts the daemon. After a
successful interactive `setup wizard` publication, a separate default-exit
menu can explicitly start the daemon and open chat or the dashboard.

Matrix homeserver values must be absolute HTTP(S) URLs without embedded
userinfo, a query, or a fragment. Slack bot-token and app-token references must
name distinct logical credentials.

`shisad[assistant]` and the local container already contain the channel client
libraries. For a source checkout, install the matching dependency group:

```bash
uv --no-config sync --frozen --group channels-runtime
```

### Discord

**Setup:**

1. Go to https://discord.com/developers/applications and click **New Application**.
2. Go to **Bot** tab → click **Reset Token** → copy the **bot token**.
3. Under **Bot** tab: disable **Public Bot**. Under **Privileged Gateway Intents**, enable **Message Content Intent**.
4. Go to **OAuth2** tab → **URL Generator**:
   - Scopes: `bot`
   - Bot Permissions: `Send Messages`, `Read Message History`, `View Channels`
   - Also select `Create Public Threads` and `Send Messages in Threads` when
     enabling the optional thread mode below.
   - Copy the generated URL and open it to invite the bot to your server.
5. Get your **Discord user ID**: enable Developer Mode (Settings → Advanced → Developer Mode), right-click your name → **Copy User ID**.

**Config:**

```bash
SHISAD_DISCORD_ENABLED=true
SHISAD_DISCORD_BOT_TOKEN_REF=channel.discord
SHISAD_DISCORD_DEFAULT_CHANNEL_ID=<channel-id>
SHISAD_DISCORD_USE_THREADS=true  # optional; default false
SHISAD_DISCORD_TRUSTED_USERS='["<your-discord-user-id>"]'
```

For example, register the reference to an operator-supplied environment
variable, then preview it without connecting:

```bash
shisad credential set channel.discord \
  --backend env --locator DISCORD_BOT_TOKEN
shisad setup channel --channel discord \
  --bot-token-ref channel.discord \
  --default-target <channel-id> \
  --trusted-user <your-discord-user-id> \
  --skip-probe
```

**Verify:** Start the daemon, then `@mention` the bot in a guild channel (e.g., `@shisad hello`). The bot only responds to `@mentions` in guild channels; DMs currently do not require a mention.

With `SHISAD_DISCORD_USE_THREADS=true`, an addressed parent message creates a
thread named from its Discord message ID. Follow-up messages and all response,
approval, and result delivery remain bound to that thread and reuse its
session. If thread creation is unavailable, the bot reports the required
permissions in the parent and does not silently continue with flat delivery.
An unresolved thread target also fails without falling back to the parent.
Discord channel rules for a thread are inherited from its parent channel ID.

**Optional public-channel policy:** Configure `SHISAD_DISCORD_CHANNEL_RULES` as
JSON when the bot should also serve a shared Discord channel. Rules are
guild/channel scoped; missing config stays default-deny, and explicit
`exclude_channels` / `denied_users` entries win over broad public grants.
Set `guild_id: "*"` only when you intentionally want a cross-guild rule; empty
or omitted `channels` means every channel in the matching guild except
`exclude_channels`.

```bash
SHISAD_DISCORD_CHANNEL_RULES='[
  {
    "guild_id": "<guild-id>",
    "channels": ["<public-channel-id>"],
    "mode": "read-along",
    "public_enabled": true,
    "public_tools": ["web.search"],
    "relevance_keywords": ["docs", "release"],
    "cooldown_seconds": 300,
    "proactive_marker": "[proactive]"
  }
]'
```

`mention-only` responds only when addressed, `read-along` observes all messages
but only replies proactively on configured keyword matches and cooldown, and
`passive-observe` records observed channel context without replying. Public and
trusted-guest sessions are ephemeral and do not receive owner-private memory or
the owner session's full tool surface.

### Telegram

**Setup:**

1. Open Telegram and search for `@BotFather`, then send `/newbot`.
2. Enter a display name and a username ending in `bot`.
3. BotFather replies with a **bot token**. Copy it.
4. Get your **numeric user ID**: search for `@userinfobot` in Telegram, send any message, copy the ID.
5. Search for your bot's username and press **Start** to open a private chat.

**Config:**

```bash
SHISAD_TELEGRAM_ENABLED=true
SHISAD_TELEGRAM_BOT_TOKEN_REF=channel.telegram
SHISAD_TELEGRAM_TRUSTED_USERS='["<your-numeric-user-id>"]'
```

**Verify:** Start the daemon, then send a message to your bot in Telegram.

### Slack

**Setup:**

1. Create a new app at https://api.slack.com/apps (from manifest or from scratch).
2. Enable **Socket Mode** (Settings → Socket Mode → toggle on) and generate an **app-level token** (`xapp-...`) with `connections:write` scope.
3. Under **OAuth & Permissions**, add bot token scopes: `chat:write`, `channels:history`, `groups:history`, `im:history`, `mpim:history`.
4. Install the app to your workspace and copy the **bot token** (`xoxb-...`).
5. Get your **Slack user ID**: click your profile → three dots → **Copy member ID**.

**Config:**

```bash
SHISAD_SLACK_ENABLED=true
SHISAD_SLACK_BOT_TOKEN_REF=channel.slack.bot
SHISAD_SLACK_APP_TOKEN_REF=channel.slack.app
SHISAD_SLACK_TRUSTED_USERS='["<your-slack-user-id>"]'
```

**Verify:** Start the daemon, then mention the bot or DM it in Slack.

### Matrix

**Setup:**

1. Create a dedicated bot account on the chosen Matrix homeserver.
2. Obtain an access token for that account and invite it to the intended room.
3. Record the full bot user id (`@bot:example.org`), room id
   (`!room:example.org`), homeserver URL, and the Matrix user ids allowed to
   issue commands.
4. Leave E2EE enabled unless the room and deployment deliberately use an
   unencrypted test posture. E2EE availability depends on the installed Matrix
   runtime and room state.

**Config:**

```bash
SHISAD_MATRIX_ENABLED=true
SHISAD_MATRIX_HOMESERVER=https://matrix.example.org
SHISAD_MATRIX_USER_ID=@shisad:example.org
SHISAD_MATRIX_ACCESS_TOKEN_REF=channel.matrix
SHISAD_MATRIX_ROOM_ID='!room:example.org'
SHISAD_MATRIX_E2EE=true
SHISAD_MATRIX_TRUSTED_USERS='["@alice:example.org"]'
```

**Verify:** Start the daemon, send a message from an allowlisted Matrix user in
the configured room, and confirm that an unlisted user is rejected. For
multiple rooms, configure `SHISAD_MATRIX_ROOM_WORKSPACE_MAP` so each room binds
to its intended workspace rather than relying on the default room alone.

---

## Web Search Backend (Recommended)

`tool.web.search` calls a JSON search backend you supply — shisad does not
ship an embedded search index. Without a backend configured, the tool stays
registered but reports `web_search_backend_unconfigured` in live tool-status
checks and returns no results at runtime. For research-style workflows
(targeted lookups, multi-site comparisons) this materially affects output
quality, so standing up a backend is the intended setup.

The runtime expects a SearxNG-style `/search?q=...&format=json` endpoint. A
local [SearxNG](https://docs.searxng.org/) instance is the typical dev setup;
any SearxNG-compatible endpoint works.

### Local Source Checkout Setup

For a local `./run.sh` or `runner/harness.sh` checkout, one working setup is a
loopback-only SearxNG container with JSON responses enabled:

```bash
mkdir -p .local/searxng
cat > .local/searxng/settings.yml <<'YAML'
use_default_settings: true

search:
  formats:
    - html
    - json

server:
  secret_key: "replace-with-random-secret"
  limiter: false
  public_instance: false
YAML

sudo docker run -d \
  --name shisad-searxng \
  --restart unless-stopped \
  -p 127.0.0.1:8080:8080 \
  -v "$PWD/.local/searxng:/etc/searxng:rw" \
  searxng/searxng:latest
```

Then add the shisad-side settings to `runner/.env` (gitignored):

```env
SHISAD_WEB_SEARCH_ENABLED=true
SHISAD_WEB_SEARCH_BACKEND_URL=http://127.0.0.1:8080
SHISAD_WEB_ALLOWED_DOMAINS=127.0.0.1,localhost
```

IP-literal, `localhost`, and `.local` / `.internal` / `.lan` backend hosts must
be present in the effective web allowlist. For source-checkout runner setups,
set that list with `SHISAD_WEB_ALLOWED_DOMAINS`; when the variable is unset,
the daemon falls back to policy egress hosts. The local recipe above uses
`127.0.0.1,localhost` for that reason. Public backend hosts do not need an
allowlist entry just to run `web.search`, but listing the backend and common
result hosts preapproves backend redirects and later `web.fetch` calls. See
`docs/ENV-VARS.md` for the full web-tooling variable reference. In env files,
prefer the comma-separated list form shown above.

Restart the shisad daemon after changing `SHISAD_WEB_*` values. The search
backend URL and allowlist are read at daemon startup, so exporting variables in
a separate CLI terminal does not update an already-running daemon.

```bash
bash runner/harness.sh stop
bash runner/harness.sh start --no-debug
```

After restart, startup logs should show the configured backend and allowlist
count:

```text
Config: web.search=enabled backend=http://127.0.0.1:8080 web.fetch=enabled allowed_domains=2 ...
```

Verify the backend directly first:

```bash
curl -fsS 'http://127.0.0.1:8080/search?q=shisad&format=json' -o /tmp/searxng.json
python - <<'PY'
import json
payload = json.load(open('/tmp/searxng.json'))
print(len(payload.get('results', [])))
PY
```

Then verify through shisad:

```bash
uv run shisad web search "latest Python release" --limit 3

# Or use the runner wrapper, which also targets the shared default socket:
bash runner/harness.sh shisad web search "latest Python release" --limit 3
```

Troubleshooting:

| Symptom | Likely cause | Fix |
|---|---|---|
| `web_search_backend_unconfigured` | The running daemon started without `SHISAD_WEB_SEARCH_BACKEND_URL`. | Set it in `runner/.env` or `SHISAD_ENV_FILE`, then restart the daemon. |
| `search_backend_invalid_json` | SearxNG JSON output is not enabled, or the backend URL is not the SearxNG base URL. | Add `json` under `search.formats` in `settings.yml`, restart SearxNG, and verify `/search?q=shisad&format=json` with `curl`. |
| `ip_literal_not_allowlisted`, `local_destination_not_allowlisted`, or backend host not allowlisted | The configured backend host is an IP literal, `localhost`, or `.local` / `.internal` / `.lan` name that is missing from the effective web allowlist. | Add the actual backend host to `SHISAD_WEB_ALLOWED_DOMAINS` for runner/env-file setups (for the local recipe: `127.0.0.1,localhost`), or to policy egress hosts when using policy fallback, then restart shisad. |
| Docker permission denied for `/var/run/docker.sock` | The current user cannot access the Docker daemon. | Run the container command with `sudo`, add the user to the `docker` group, or use a rootless/container alternative. |

---

## Operational CLI Output

Treat diagnostic JSON from shisad CLI commands as local operational data.
`shisad task list --json` prints the raw scheduler task-list response, which
can include user-authored task text, schedule metadata, delivery-channel
display fields, and identifiers. Do not paste this output into shared logs,
support tickets, or issue reports without reviewing and redacting it.

### Audit lifecycle

The v0.8.2 development tree verifies the retained main and control-plane audit
chains before their owning runtime begins serving work. Each stream rotates
before its active segment would exceed 32 MiB and normally retains four linked
archives plus the active segment. A retention deletion failure preserves the
uncertain archive and reports degraded retention instead of discarding audit
history.

While the daemon is running, `daemon.status` reports the live main and
control-plane audit owners, including a latched unavailable state. The
human-readable `audit verify` output includes state, counts, archive count,
reason code, and permission/directory-sync capability without exposing paths.

Inspect retained audit state while the daemon is stopped:

```bash
shisad audit verify
shisad audit verify --json
shisad audit query --all --json
```

Verification covers every retained entry and adjacent segment link. Startup
refuses corrupted active or archived state; it does not truncate, quarantine,
or start a replacement chain automatically. Stop the daemon, preserve the data
root, run `shisad audit verify`, and restore a known-good whole-data-root backup
when verification fails. A main-stream persistence failure prevents event
subscriber dispatch and requests daemon shutdown. A control-plane persistence
failure cannot precede an unrecorded control-plane state change: state-changing
operations record their event or a write-ahead intent first, and later
decisions are rejected. Neither path continues through an unaudited fallback.

---

## Host Hardening (Optional)

For production or internet-facing deployments:

```bash
sudo apt install --no-install-recommends -y ufw fail2ban
```

- Set timezone: `sudo timedatectl set-timezone UTC`
- Enable fail2ban: `sudo systemctl enable --now fail2ban`
- Enable SSH-only firewall:
  ```bash
  sudo ufw default deny incoming
  sudo ufw default allow outgoing
  sudo ufw allow OpenSSH
  sudo ufw enable
  ```
- Verify time sync: `timedatectl` (look for `System clock synchronized: yes`)

---

## Troubleshooting

**`doctor.check` reports `policy_file_missing`:**
Create a policy file (copy `runner/policy.default.yaml` as a starting point) and restart the daemon.

**`doctor.check` reports `<channel>_dependency_missing`:**
Install `shisad[assistant]`, or run
`uv --no-config sync --frozen --group channels-runtime` in a source checkout.
A dependency being installed does not enable a channel; verify its token and
`SHISAD_<CHANNEL>_ENABLED` setting separately.

**`uv sync --extra security-runtime` fails:**
`security-runtime` is a dependency group, not an optional extra. Use
`uv --no-config sync --frozen --group security-runtime` or the combined
source-checkout command
`uv --no-config sync --frozen --group security-runtime --group dev
--group channels-runtime`. For package installs, use
`uv pip install 'shisad[promptguard]'` or combine it with the consumer profile
as `shisad[assistant,promptguard]`.

**Startup logs say PyTorch was not found:**
This is expected when only `security-runtime` is installed. The daemon runtime
uses PromptGuard's `onnxruntime`/`transformers` path through
`textguard[promptguard]`; PyTorch is only in `security-build` for model
build/export workflows.

**`doctor.check` reports `<channel>_not_connected`:**
Verify bot/app tokens and channel auth configuration.

**Daemon start fails with `PermissionError` on socket path:**
The default socket path is per-user and should not require root. If you
overrode `SHISAD_SOCKET_PATH`, set it to a user-writable directory or unset it
and restart with the default. Use `bash runner/harness.sh env` to inspect the
effective socket path.

**`web fetch` fails with `CERTIFICATE_VERIFY_FAILED`:**
Install or update the CA trust bundle: `sudo apt install ca-certificates`.

**`fs write` returns `explicit_confirmation_required`:**
This is the expected confirmation gate. Rerun with `--confirm`.

**`session.message` fails with planner parse errors:**
Ensure you are on the latest installed artifact (or run
`uv --no-config sync --frozen --group dev --group channels-runtime` in a source
checkout), restart the daemon, and verify `SHISAD_MODEL_*` settings point at an
OpenAI-compatible endpoint that supports JSON response formatting.

**Env values with JSON lists cause `SettingsError`:**
If the env file is shell-sourced, switch list fields to comma-separated values,
for example `SHISAD_WEB_ALLOWED_DOMAINS=a.com,b.com`, or quote the whole JSON
array value with single quotes. Unquoted JSON arrays such as
`SHISAD_WEB_ALLOWED_DOMAINS=["a.com","b.com"]` lose their inner quotes during
shell parsing and arrive as invalid JSON.

---

## Further Reading

- `docs/ENV-VARS.md` — full environment variable reference
- `docs/TOOL-STATUS.md` — point-in-time tool snapshot
- `docs/SECURITY.md` — security architecture and threat model
- `docs/DESIGN-PHILOSOPHY.md` — governing design principles
- `runner/RUNBOOK.md` — runner harness operator runbook
- `runner/README.md` — runner harness internals
