# Multi-Factor Approval (2FA)

shisad supports multi-factor confirmation for actions that policy marks as
requiring more than a simple click. This guide covers what is available today,
how to set it up, and what the approval levels mean.

**2FA is opt-in.** No multi-factor confirmation is required until you enroll
a credential. The standard L0 software confirmation flow (click-to-approve)
remains the default. Once you register a TOTP secret, passkey, or signer key,
the enrolled methods become available for policy rules that require them.

---

## How It Works

When the agent proposes an action that requires confirmation, the daemon creates
an **approval request** with a required strength level. The operator satisfies
the request using a registered confirmation method (TOTP code, passkey tap,
hardware signer, etc.). Only after verification does the action execute.

Every approval is bound to a specific pending action, recorded in the audit
trail with the method used, the credential that satisfied it, and the strength
of the proof.

---

## Approval Levels

Policy rules reference five approval levels. Higher levels provide stronger
proof that a specific operator authorized a specific action.

| Level | Name | What it proves |
|---|---|---|
| L0 | `software` | Session holder clicked approve (current default) |
| L1 | `reauthenticated` | Operator presented a registered factor (e.g. TOTP code) |
| L2 | `bound_approval` | Operator approved *this specific request* via a challenge-bound method (e.g. passkey) |
| L3 | `signed_authorization` | A registered credential cryptographically signed the canonical action intent |
| L4 | `trusted_display_authorization` | Same as L3, plus the operator reviewed the action on an independent trusted display (e.g. Ledger Stax) |

Most operators will use L1 (TOTP) as a baseline and L2 (passkey) for
higher-risk actions. L3 and L4 are available for environments that need
independently verifiable authorization or hardware-trusted review.

---

## Available Methods

### TOTP (L1 — reauthenticated)

Standard time-based one-time passwords (RFC 6238). Works with any authenticator
app (Google Authenticator, Authy, 1Password, etc.).

**What it gives you:** proof that the operator is present now. TOTP codes are
not bound to a specific action — they prove identity, not authorization of a
particular request.

**Setup:**

```bash
# Register a TOTP credential
shisactl 2fa register --method totp --user alice --name "phone-authenticator"
```

This prints an `otpauth://` URI. Add it to your authenticator app (paste or
scan as QR). The registration also generates 8 single-use recovery codes —
store these securely offline.

**Confirming an action:**

When an action requires L1 confirmation, the daemon prompts you through your
active channel (chat or web). Reply with your 6-digit TOTP code directly in
chat, or enter it on the approval web page if you have an approval origin
configured.

You can also confirm via the CLI if you prefer:

```bash
shisad action confirm <ID> --nonce <NONCE> --totp-code 123456
```

Recovery codes work the same way:

```bash
shisad action confirm <ID> --nonce <NONCE> --recovery-code XXXX-XXXX
```

**Limitations:** TOTP codes are time-windowed (30 seconds, with a +/-1 window
for clock drift). Each code can only be used once within its window. TOTP
cannot satisfy `bound_approval` or higher policies because the code is not
tied to a specific action.

### WebAuthn / Passkeys (L2 — bound approval)

FIDO2/WebAuthn passkeys provide challenge-bound confirmation. The cryptographic
challenge is derived from the approval request itself, so the proof is tied to
the exact action being approved.

**What it gives you:** proof that the operator approved *this specific pending
request*, not just that they are present.

**Prerequisites:**

- A stable HTTPS approval origin (set `SHISAD_APPROVAL_ORIGIN`)
- A WebAuthn-capable authenticator (platform passkey, YubiKey, etc.)

**Setup:**

```bash
# Configure the approval origin (the hostname operators will open in a browser)
export SHISAD_APPROVAL_ORIGIN="https://approve.example.com"

# Optional: run the setup helper for cert provisioning
shisad approval setup --provider caddy  # or --provider tailscale

# Register a passkey
shisactl 2fa register --method webauthn --user alice --name "yubikey-5-nfc"
```

Registration opens a browser ceremony page where you complete the WebAuthn
enrollment with your authenticator.

**Confirming an action:**

When an action requires L2, the daemon provides an approval link:

```bash
$ shisad action confirm <ID>
Approval required: deploy.production (level: bound_approval)
Open this URL to approve:
  https://approve.example.com/approve/<ID>?token=...

Waiting for approval... (Ctrl-C to cancel)
```

Open the link in your browser, review the action summary, and tap your
authenticator. The browser POSTs the WebAuthn assertion back to the daemon.

**Approval origin options:**

| Deployment | How to set up |
|---|---|
| Public hostname | Point DNS at your host, use Let's Encrypt or Caddy for TLS |
| Tailscale | Use your Tailscale HTTPS hostname (automatic TLS) |
| VPN / private mesh | Same as public, within the mesh |
| SSH-only (no public URL) | Use the local helper instead (see below) |

If `SHISAD_APPROVAL_ORIGIN` is not configured, the browser ceremony surface is
unavailable. Use the local helper or TOTP instead.

### Local Helper — `shisad-approver` (L2 — bound approval)

For SSH-only or air-gapped deployments where a browser ceremony is not
practical, the `shisad-approver` helper runs on the operator's local machine
and bridges FIDO2 interactions over an authenticated channel.

**What it gives you:** the same L2 bound-approval strength as browser WebAuthn,
but without needing a public HTTPS endpoint.

**Setup:**

The local helper connects to the daemon over SSH (default) or via a paired
shared-secret channel:

```bash
# SSH tunnel mode (default — uses your existing SSH access)
shisad-approver connect --daemon ssh://user@host

# Standalone mode (no SSH)
shisactl approver pair   # one-time pairing on the daemon
shisad-approver connect --daemon wss://host:port --token <pairing-token>
```

**Note:** Credentials registered via the local helper use a different
credential pool than browser-registered passkeys. They are scoped to the
local helper's rpId and are not interchangeable.

### Enterprise / Cloud KMS (L3 — signed authorization)

For environments that need independently verifiable authorization, shisad can
delegate signing to an external KMS endpoint. The daemon sends an
`IntentEnvelope` (a canonical, signable description of the action) to the KMS,
which returns a cryptographic signature after its own approval workflow.

**What it gives you:** third-party-verifiable proof that a registered key signed
the exact action intent. The signature can be independently verified outside
shisad.

**Setup:**

```bash
# Point the daemon at your KMS endpoint
export SHISAD_SIGNER_KMS_URL="https://kms.example.com/sign"
export SHISAD_SIGNER_KMS_BEARER_TOKEN="..."   # if your KMS requires auth

# Register the signing key's public key
shisactl signer register --user alice --key-id kms:finance-primary \
    --public-key /path/to/public-key.pem

# List registered signer keys
shisactl signer list

# Revoke a key
shisactl signer revoke --key-id kms:finance-primary
```

The daemon verifies the returned signature locally against the registered
public key. The KMS can deny service but cannot forge approvals without a
matching private key.

---

## Policy Configuration

Approval levels are configured per-tool in your policy file.

**Basic examples:**

```yaml
tools:
  # Simple confirmation (L0 software click, the default)
  "shell.exec":
    require_confirmation: true

  # Require TOTP or passkey re-authentication
  "git.push":
    confirmation:
      level: reauthenticated
      methods: [totp, webauthn]
      timeout_seconds: 300

  # Require challenge-bound passkey approval
  "deploy.production":
    confirmation:
      level: bound_approval
      methods: [webauthn]
      allowed_credentials:
        - webauthn:yubikey-5-nfc
      require_capabilities:
        binding_scope: approval_envelope
        principal_binding: true
      fallback:
        mode: deny
      timeout_seconds: 300

  # Require KMS-signed authorization
  "admin.key_unwrap":
    confirmation:
      level: signed_authorization
      methods: [kms]
      require_capabilities:
        binding_scope: full_intent
        third_party_verifiable: true
      fallback:
        mode: deny
      timeout_seconds: 600
```

**Fallback behavior:** By default, if the required method is unavailable, the
action is denied. You can configure explicit fallback levels:

```yaml
fallback:
  mode: allow_levels
  allow_levels: [reauthenticated]  # allow TOTP as fallback
```

No implicit downgrades occur. All fallback use is recorded in the audit trail.

**Risk-based escalation:** The global risk scoring system can also drive
approval levels based on action risk scores:

```yaml
risk_policy:
  confirmation_levels:
    - score_gte: 0.45
      level: software
    - score_gte: 0.60
      level: reauthenticated
    - score_gte: 0.70
      level: bound_approval
    - score_gte: 0.80
      level: signed_authorization
```

The highest required level wins (tool policy or risk score).

---

## Managing Credentials

```bash
# List all registered 2FA credentials
shisactl 2fa list
shisactl 2fa list --method totp
shisactl 2fa list --user alice

# Revoke a credential
shisactl 2fa revoke --method totp --user alice
shisactl 2fa revoke --method webauthn --user alice --credential-id <ID>

# List/revoke signer keys (L3+)
shisactl signer list
shisactl signer revoke --key-id <KEY_ID>
```

**Credential storage:** Approval factors are stored in a daemon-owned JSON file
(default path controlled by `SHISAD_SECURITY_APPROVAL_FACTOR_STORE_PATH`).
This file is not encrypted at rest in the current release — protect it with
filesystem permissions.

---

## Recovery

**Lost TOTP device:** Use one of the 8 single-use recovery codes generated at
enrollment. Each code works once and provides L1-equivalent confirmation. After
regaining access, revoke the lost credential and re-enroll a replacement.

**Lost passkey or hardware key:** SSH into the host and revoke the lost
credential:

```bash
shisactl 2fa revoke --method webauthn --user alice --credential-id <ID>
```

Then register a replacement, or lower the tool's policy requirement until you
have a new key.

There is no special in-band recovery ceremony for high-tier credentials. If
you have lost both your hardware key and system-level access, that is a
different class of problem — restore from backups or re-provision.

---

## Environment Variables

| Variable | Purpose |
|---|---|
| `SHISAD_APPROVAL_ORIGIN` | HTTPS origin for the WebAuthn browser ceremony (e.g. `https://approve.example.com`) |
| `SHISAD_APPROVAL_RP_ID` | WebAuthn relying-party ID (defaults to approval-origin hostname) |
| `SHISAD_APPROVAL_BIND_HOST` | Local listener bind address for ceremony pages |
| `SHISAD_APPROVAL_BIND_PORT` | Local listener bind port for ceremony pages |
| `SHISAD_APPROVAL_LINK_TTL_SECONDS` | Expiry for registration and approval links |
| `SHISAD_APPROVAL_RATE_LIMIT_WINDOW_SECONDS` | Rate-limit window for approval attempts |
| `SHISAD_APPROVAL_RATE_LIMIT_MAX_ATTEMPTS` | Max attempts per rate-limit window |
| `SHISAD_SIGNER_KMS_URL` | Enterprise KMS signing endpoint URL |
| `SHISAD_SIGNER_KMS_BEARER_TOKEN` | Bearer token for KMS endpoint authentication |
| `SHISAD_SECURITY_APPROVAL_FACTOR_STORE_PATH` | Path to the durable credential store |

See [ENV-VARS.md](ENV-VARS.md) for the complete environment variable reference.

---

## Audit Trail

Every confirmation records:

- Approval level and method used
- Approver identity and credential ID
- Binding scope (none, action digest, approval envelope, or full intent)
- Review surface (host-rendered, browser, provider UI, trusted device)
- Whether a fallback was used
- Evidence hash for tamper detection

For L3+ signed approvals, the audit trail also includes the intent envelope
hash, signature, and signer key ID.

---

## What's Not Yet Available

- **Trusted-display authorization (L4):** Consumer Ledger clear-signing and
  other trusted-display hardware flows are designed but not yet shipped. The
  protocol and policy language are ready; the device integration is follow-on.
- **Push notification approvals:** Planned as a future L1 method.
- **Multi-approver / quorum:** The schema supports multiple principals and
  credentials, but M-of-N approval is not yet enforced. Environments that need
  quorum today should use an Enterprise KMS that enforces it on their side.
- **At-rest encryption for credential store:** The approval-factor store is
  currently plaintext JSON. At-rest encryption is follow-on.

---

## Further Reading

- [SECURITY.md](SECURITY.md) — overall security architecture
- [ENV-VARS.md](ENV-VARS.md) — full environment variable reference
- [DESIGN-PHILOSOPHY.md](DESIGN-PHILOSOPHY.md) — governing design principles
