# Deploy and Run

Users and agents looking to set up shisad on their own system should start here.

shisad is a long-running daemon — it is designed to run on a dedicated instance or
container, not inside your development environment. We recommend a standalone VM
(cloud instance or local VM) or container as the deployment target.

## One-Click Instance Deployment

Coming soon. For now, follow the manual paths below.

---

## Prerequisites

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
uv sync --group dev --extra chat
```

If you want local PromptGuard/YARA runtime checks in the daemon, include the
security runtime dependency group:

```bash
uv sync --group security-runtime --group dev --extra chat
```

`security-runtime`, `security-build`, `channels-runtime`, and `coverage` are uv
dependency groups from `[dependency-groups]`; install them with `--group`. The
chat UI dependencies are a project optional extra; install them with
`--extra chat`.

Optional groups:

```bash
uv sync --group security-runtime    # YARA + local ONNX PromptGuard runtime checks
uv sync --group security-build      # PromptGuard download/export/model-pack build tooling
uv sync --group channels-runtime    # Matrix, Discord, Telegram, Slack
uv sync --group coverage            # pytest-cov
```

`security-build` is only needed for PromptGuard model export/download/build
workflows. It is heavier than `security-runtime` and includes PyTorch. Daemon
operation with `security-runtime` alone should have `onnxruntime` and
`transformers` available but not `torch`; if Transformers logs "PyTorch was not
found" during startup in that profile, that warning is expected and does not
mean the daemon runtime group was installed incorrectly.

## Preflight Checklist

Before starting the daemon:

- [ ] Python 3.12+ and `uv` installed
- [ ] At least one LLM provider credential available (see provider table below)
- [ ] Data directory writable (default: `~/.local/share/shisad`)
- [ ] Socket path writable (default: `/tmp/shisad/control.sock`)
- [ ] Optional: at least one channel token (Discord, Telegram, or Slack)
- [ ] Optional: policy file created (`runner/policy.default.yaml` is a starting point)

## Recommended: Runner Harness

The runner harness is the default local operator path. It handles env isolation,
secret loading, policy bootstrapping, and daemon lifecycle.

Quick start:

```bash
bash runner/harness.sh start       # background; requires tmux
bash runner/harness.sh start --fg  # foreground; no tmux required
bash runner/harness.sh status
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

For full runner behavior, isolated instance patterns, and troubleshooting, see
`runner/RUNBOOK.md` and `runner/README.md`.

## Manual Daemon Start

If you do not want to use the runner harness, set a minimal baseline:

```bash
export SHISAD_DATA_DIR="$HOME/.local/share/shisad"
export SHISAD_SOCKET_PATH="/tmp/shisad/control.sock"
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

In another shell:

```bash
uv run shisad status
uv run shisad doctor check --component all
uv run shisad tui --plain
```

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

Install channel runtime dependencies first:

```bash
uv sync --group channels-runtime
```

### Discord

**Setup:**

1. Go to https://discord.com/developers/applications and click **New Application**.
2. Go to **Bot** tab → click **Reset Token** → copy the **bot token**.
3. Under **Bot** tab: disable **Public Bot**. Under **Privileged Gateway Intents**, enable **Message Content Intent**.
4. Go to **OAuth2** tab → **URL Generator**:
   - Scopes: `bot`
   - Bot Permissions: `Send Messages`, `Read Message History`, `View Channels`
   - Copy the generated URL and open it to invite the bot to your server.
5. Get your **Discord user ID**: enable Developer Mode (Settings → Advanced → Developer Mode), right-click your name → **Copy User ID**.

**Config:**

```bash
SHISAD_DISCORD_ENABLED=true
SHISAD_DISCORD_BOT_TOKEN=<bot-token>
SHISAD_DISCORD_DEFAULT_CHANNEL_ID=<channel-id>
SHISAD_CHANNEL_IDENTITY_ALLOWLIST='{"discord":["<your-discord-user-id>"]}'
```

**Verify:** Start the daemon, then `@mention` the bot in a guild channel (e.g., `@shisad hello`). The bot only responds to `@mentions` in guild channels; DMs are always processed without a mention.

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
SHISAD_TELEGRAM_BOT_TOKEN=<bot-token>
SHISAD_CHANNEL_IDENTITY_ALLOWLIST='{"telegram":["<your-numeric-user-id>"]}'
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
SHISAD_SLACK_BOT_TOKEN=<xoxb-token>
SHISAD_SLACK_APP_TOKEN=<xapp-token>
SHISAD_CHANNEL_IDENTITY_ALLOWLIST='{"slack":["<your-slack-user-id>"]}'
```

**Verify:** Start the daemon, then mention the bot or DM it in Slack.

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
Install channel runtime dependencies: `uv sync --group channels-runtime`.

**`uv sync --extra security-runtime` fails:**
`security-runtime` is a dependency group, not an optional extra. Use
`uv sync --group security-runtime` or the combined source-checkout command
`uv sync --group security-runtime --group dev --extra chat`.

**Startup logs say PyTorch was not found:**
This is expected when only `security-runtime` is installed. The daemon runtime
uses `onnxruntime`/`transformers`; PyTorch is only in `security-build` for model
build/export workflows.

**`doctor.check` reports `<channel>_not_connected`:**
Verify bot/app tokens and channel auth configuration.

**Daemon start fails with `PermissionError` on socket path:**
The default socket path may require root. For non-root operation, set `SHISAD_SOCKET_PATH` to a user-writable path (e.g., `$HOME/.local/share/shisad/control.sock`). Ensure your shell is loading the env file before starting the daemon.

**`web fetch` fails with `CERTIFICATE_VERIFY_FAILED`:**
Install or update the CA trust bundle: `sudo apt install ca-certificates`.

**`fs write` returns `explicit_confirmation_required`:**
This is the expected confirmation gate. Rerun with `--confirm`.

**`session.message` fails with planner parse errors:**
Ensure you are on the latest code (`uv sync --group dev --extra chat`), restart the daemon, and verify `SHISAD_MODEL_*` settings point at an OpenAI-compatible endpoint that supports JSON response formatting.

**Env values with JSON lists cause `SettingsError`:**
Wrap JSON values in single quotes in env files: `SHISAD_WEB_ALLOWED_DOMAINS='["a.com","b.com"]'`.

---

## Further Reading

- `docs/ENV-VARS.md` — full environment variable reference
- `docs/TOOL-STATUS.md` — point-in-time tool snapshot
- `docs/SECURITY.md` — security architecture and threat model
- `docs/DESIGN-PHILOSOPHY.md` — governing design principles
- `runner/RUNBOOK.md` — runner harness operator runbook
- `runner/README.md` — runner harness internals
