# Multi-Factor Approval (2FA)

> **v0.6.3 status:** The approval protocol, credential store, and shipped
> backends described here are implemented and tested. TOTP confirmation now
> works through trusted chat / command replies and through the CLI. Passkey
> (WebAuthn) and signer approvals already work via browser and remote KMS
> respectively. QR code rendering for TOTP enrollment is also in v0.6.3.
> Entering a TOTP code on the approval web page is not shipped yet; browser
> approval today is WebAuthn only.

---

## Why Use 2FA

shisad is an AI agent that can take real actions on your behalf: run shell
commands, push code, send messages, make API calls. By default, risky actions
require you to click "approve" before they execute. That click proves someone
with your session approved, but it does not prove it was *you* specifically, and
it does not bind the approval to a particular action.

Multi-factor approval (2FA) adds stronger proof. Depending on the method you
choose, it can prove:

- **You are present now** (not just that your session is open).
- **You approved this exact action** (not just that you clicked something).
- **A specific registered credential signed the action** (independently
  verifiable by third parties).

The stronger the proof, the harder it is for a compromised session, a prompt
injection, or a stolen token to authorize actions you did not intend.

2FA is **opt-in**. If you do not enroll any factor, everything works exactly
as before — approvals use the standard L0 software confirmation flow (click to
approve). You only need to set up 2FA if you want stronger guarantees for
specific actions.

---

## Key Concepts

### Approval levels

shisad uses five approval levels. Each level represents a different strength of
proof. Policy rules reference these levels to say "this action requires at
least this much proof."

| Level | Policy value | What it proves | Example method |
|---|---|---|---|
| L0 | `software` | Someone with the current session clicked approve | Default click-to-confirm |
| L1 | `reauthenticated` | Operator presented a registered secret (proves presence) | TOTP code from authenticator app |
| L2 | `bound_approval` | Operator approved *this specific pending action* (cryptographically bound) | Passkey / YubiKey tap in browser |
| L3 | `signed_authorization` | Registered credential signed a canonical description of the action (independently verifiable) | Enterprise KMS with approval workflow |
| L4 | `trusted_display_authorization` | Same as L3, plus the operator reviewed the action on an independent hardware display | Ledger Stax clear-signing (*not yet shipped*) |

**Higher is not always better.** L1 (TOTP) is simple and covers the most
common risk — someone else using your open session. L2 (passkey) is stronger
but requires a browser. L3 (KMS) is for environments that need third-party
audit trails. Use the level that matches the risk of the action.

### Confirmation flow

1. The agent proposes an action (e.g., `shell.exec`).
2. The policy engine checks whether that action requires confirmation, and at
   what level.
3. The daemon creates a **pending action** with an approval request.
4. You satisfy the request using a registered method at or above the required
   level.
5. The daemon verifies your proof, records it in the audit trail, and executes
   the action.

If you do not respond before the timeout, the action is denied (fail-closed).

### What is a "factor"

A factor is a registered credential that the daemon can verify. Examples:

- A **TOTP secret** shared between your authenticator app and the daemon
- A **passkey** (WebAuthn credential) registered in your browser or on a
  hardware key like a YubiKey
- A **signer public key** whose matching private key lives in an Enterprise
  KMS or hardware wallet

You enroll factors with `shisad 2fa register` (for TOTP and passkeys) or
`shisad signer register` (for KMS/signing keys). The daemon stores the
credential in its factor store. You can list, inspect, and revoke factors at
any time.

---

## Before You Start

- The daemon must be running and your CLI must be able to reach the control
  socket.
- `shisad` and `shisactl` are the same CLI entrypoint. This doc uses `shisad`.

### Useful commands

| Command | What it does |
|---|---|
| `shisad action pending` | List actions waiting for your approval |
| `shisad action confirm <ID>` | Approve a pending action (auto-resolves nonce from pending state) |
| `shisad action confirm <ID> --nonce <NONCE>` | Approve with an explicit decision nonce (from `action pending` output) |
| `shisad action reject <ID> --nonce <NONCE>` | Reject a pending action |
| `shisad 2fa list` | List enrolled TOTP and passkey credentials |
| `shisad signer list` | List enrolled signer keys |

---

## L1: TOTP (Authenticator Apps)

**What it is:** Time-based One-Time Passwords. Your authenticator app
generates a new 6-digit code every 30 seconds. You enter the code to prove
you have access to the registered secret.

**What it proves:** You are present now and hold the enrolled device. TOTP
does *not* prove which specific action you are approving — the code is the same
regardless of what is pending. This is why TOTP is L1 (reauthenticated), not
L2 (bound approval).

**Works with:** Google Authenticator, Authy, 1Password, Bitwarden, any
TOTP-compatible app.

### Enroll

```bash
shisad 2fa register --method totp --user alice --name "phone-authenticator"
```

The CLI prints:

- The raw TOTP secret (base32-encoded)
- An `otpauth://...` URI on every run. The CLI also prints a terminal QR code
  when the terminal supports Unicode block rendering and QR generation
  succeeds; otherwise the URI still prints so enrollment can continue
  manually.
- A prompt for a verification code — enter a code from your app to confirm
  enrollment

If verification succeeds, the CLI also prints **8 single-use recovery codes**.
Store these offline in a safe place. They are shown only at enrollment time and
cannot be retrieved later.

### Confirm an action

Preferred path: when the daemon posts a TOTP approval prompt to a trusted
chat / command channel, reply with your current 6-digit code.

If exactly one TOTP action is pending in that session, a bare code is enough:

```text
123456
```

If multiple TOTP actions are pending, target the specific confirmation ID:

```text
confirm <CONFIRMATION_ID> 123456
```

The pending-confirmation summary lists the active TOTP confirmation IDs.

CLI remains available as a secondary path:

```bash
shisad action confirm <CONFIRMATION_ID> --totp-code 123456
```

Recovery-code approval is still a CLI flow:

```bash
shisad action confirm <CONFIRMATION_ID> --recovery-code XXXX-XXXX
```

### Behavior details

| Property | Value |
|---|---|
| Approval level | L1 (`reauthenticated`) |
| Code lifetime | 30 seconds |
| Clock tolerance | +/- 1 step (90-second effective window) |
| Replay protection | Each code can only be used once within its valid window |
| Recovery codes | 8 single-use codes generated at enrollment |
| Binding | None — codes are not tied to a specific action |

---

## L2: Passkey in Browser (WebAuthn)

**What it is:** FIDO2/WebAuthn passkeys. When an action needs approval, the
daemon provides a URL. You open it in your browser, review the action summary,
and tap your authenticator (platform passkey, YubiKey, fingerprint reader,
etc.). The browser sends a cryptographic proof back to the daemon.

**What it proves:** You approved *this specific pending action*. The
cryptographic challenge is derived from the approval request itself
(`approval_envelope_hash`), so the proof is bound to the exact action — not
just to the session or a timestamp.

**Why it is stronger than TOTP:** A TOTP code can satisfy any pending
approval. A passkey assertion can only satisfy the one it was challenged for.
If an attacker intercepts a TOTP code, they can use it for any pending action
within the 30-second window. A passkey assertion is useless for any other
action.

### Required setting

You must set `SHISAD_APPROVAL_ORIGIN` to enable the browser ceremony surface.
This is the HTTPS URL that operators will open in their browser.

```bash
export SHISAD_APPROVAL_ORIGIN="https://approve.example.com"
```

Rules for the origin value:

- Must be `https://` for non-loopback addresses
- Loopback (`http://127.0.0.1`, `http://localhost`) is allowed for local
  dev/tests only
- Use origin form only: `scheme://host[:port]` — no path, query, or fragment

Optional helper to print environment setup and reverse-proxy guidance:

```bash
shisad approval setup --provider caddy
# or
shisad approval setup --provider tailscale
```

If `SHISAD_APPROVAL_ORIGIN` is unset, browser WebAuthn is unavailable. Use
the local helper (below) or TOTP instead.

### Enroll a passkey

```bash
shisad 2fa register --method webauthn --user alice --name "yubikey-5-nfc"
```

The CLI prints (or opens) a registration URL. Complete the WebAuthn enrollment
in your browser with your authenticator.

### Confirm an action

```bash
shisad action confirm <CONFIRMATION_ID>
```

For WebAuthn-pending actions, the CLI:

1. Prints an approval URL
2. Optionally opens your browser
3. Waits for you to complete the ceremony

You can also open the URL directly from a chat notification or QR code if your
deployment publishes approval links to a channel.

### Deployment options for the approval origin

| Deployment | How to set up |
|---|---|
| Public hostname | Point DNS at your host; use Let's Encrypt or Caddy for TLS |
| Tailscale | Use your Tailscale HTTPS hostname (automatic TLS) |
| VPN / private mesh | Same as public, within the mesh |
| SSH-only (no public URL) | Use the local helper instead (next section) |

---

## L2: SSH/Private-Only Passkey (`shisad-approver`)

**What it is:** A local helper binary that runs on your laptop or workstation.
It bridges FIDO2 interactions over SSH to the daemon, so you get the same L2
bound-approval strength without needing a public HTTPS endpoint.

**When to use it:** SSH-only deployments, air-gapped networks, or situations
where setting up an approval origin is not practical.

### How it works in v0.6.2

Browser WebAuthn and the local helper (`local_fido2`) are alternate L2
backends:

- With `SHISAD_APPROVAL_ORIGIN` configured → browser WebAuthn is used
- Without it → local-helper L2 is available

### Enroll a helper credential

```bash
shisad-approver register \
  --ssh-target user@host \
  --remote-socket /run/shisad/control.sock \
  --user alice \
  --name "laptop-yubikey"
```

### Run the helper

```bash
shisad-approver run \
  --ssh-target user@host \
  --remote-socket /run/shisad/control.sock
```

- If the helper runs on the daemon host directly, use `--socket-path` instead
  of the SSH flags.
- `--remote-socket` should match the daemon's `SHISAD_SOCKET_PATH`.

### Credential compatibility

Browser WebAuthn credentials and local-helper credentials use **different
rpIds** and are stored in **separate credential pools**. They are not
interchangeable. If you switch from browser to helper (or vice versa), you
must enroll new credentials.

---

## L3: Signer / KMS Authorization

**What it is:** The daemon sends a canonical description of the action (an
`IntentEnvelope`) to an external signing service (Enterprise KMS, HSM, etc.).
The service signs the intent with a registered private key after its own
approval workflow. The daemon verifies the signature locally against the
registered public key.

**What it proves:** A specific registered credential cryptographically signed
the exact action intent. The signature is independently verifiable — anyone
with the public key can confirm the approval without trusting shisad.

**When to use it:** Compliance environments, regulated workflows, or any
situation where you need a third-party-verifiable audit trail.

### Required settings

```bash
# The HTTPS endpoint your KMS exposes for signing requests
export SHISAD_SIGNER_KMS_URL="https://kms.example.com/sign"

# Optional: bearer token if your KMS requires authentication
export SHISAD_SIGNER_KMS_BEARER_TOKEN="..."
```

If `SHISAD_SIGNER_KMS_URL` is unset, the `kms` signer method is unavailable
and policies requiring it fail closed with an actionable error.

### Register a signer public key

```bash
shisad signer register \
  --user alice \
  --key-id kms:finance-primary \
  --public-key /path/to/public-key.pem
```

The public key must be PEM-encoded Ed25519 or ECDSA secp256k1. The daemon
verifies returned signatures against this key — the KMS can deny service but
cannot forge approvals without the matching private key.

### Manage signer keys

```bash
# List registered signer keys
shisad signer list

# Revoke a key (permanent — revoked key IDs cannot be re-registered)
shisad signer revoke --key-id kms:finance-primary
```

---

## Policy Configuration

Approval requirements are configured per tool in your policy file under
`tools.<tool_name>.confirmation`.

### L0: simple confirmation (the default)

```yaml
tools:
  shell.exec:
    require_confirmation: true
```

Anyone with the session can click approve. No factor enrollment needed.

### L1: require TOTP re-authentication

```yaml
tools:
  git.push:
    confirmation:
      level: reauthenticated
      timeout_seconds: 300
```

The operator must present a valid TOTP code (or recovery code) within 5
minutes.

### L2: require passkey-bound approval

```yaml
tools:
  deploy.production:
    confirmation:
      level: bound_approval
      methods: [webauthn]
      allowed_credentials:
        - webauthn.<credential-id>
      require_capabilities:
        principal_binding: true
        approval_binding: true
      fallback:
        mode: deny
      timeout_seconds: 300
```

The operator must complete a WebAuthn ceremony that is cryptographically bound
to this specific pending action. If the passkey is unavailable, the action is
denied (no fallback).

### L2 with L1 fallback

```yaml
tools:
  deploy.staging:
    confirmation:
      level: bound_approval
      fallback:
        mode: allow_levels
        allow_levels: [reauthenticated]
```

Try passkey first. If unavailable, accept TOTP as a fallback. The audit trail
records that a fallback was used.

> **Tip:** If you restrict `methods`, make sure a method exists at the
> fallback level too (or leave `methods` empty), otherwise the fallback may
> not route to an available backend.

### L3: require KMS-signed authorization

```yaml
tools:
  admin.key_unwrap:
    confirmation:
      level: signed_authorization
      methods: [kms]
      allowed_credentials:
        - kms:finance-primary
      require_capabilities:
        principal_binding: true
        full_intent_signature: true
        third_party_verifiable: true
      fallback:
        mode: deny
      timeout_seconds: 600
```

The daemon sends the `IntentEnvelope` to the KMS endpoint and verifies the
returned signature. No fallback — if the KMS is unreachable, the action is
denied.

### Risk-based escalation

The global risk scoring system can also drive approval levels based on action
risk scores:

```yaml
risk_policy:
  confirmation_levels:
    - threshold: 0.45
      level: software
    - threshold: 0.60
      level: reauthenticated
    - threshold: 0.70
      level: bound_approval
    - threshold: 0.80
      level: signed_authorization
```

If both tool policy and risk policy apply, the higher required level wins.

---

## Credential Management

### List enrolled factors

```bash
shisad 2fa list                          # all factors
shisad 2fa list --method totp            # TOTP only
shisad 2fa list --method webauthn        # browser passkeys only
shisad 2fa list --method local_fido2     # helper passkeys only
shisad 2fa list --user alice             # for a specific user
```

### Revoke a credential

```bash
shisad 2fa revoke --method totp --user alice
shisad 2fa revoke --method webauthn --user alice --credential-id <ID>
shisad 2fa revoke --method local_fido2 --user alice --credential-id <ID>
```

### Signer keys

```bash
shisad signer list
shisad signer revoke --key-id <KEY_ID>
```

Revoked signer key IDs are permanently tombstoned and cannot be re-registered.

---

## Recovery

| Scenario | What to do |
|---|---|
| Lost TOTP device | Use one of the 8 single-use recovery codes, then revoke the old credential and re-enroll |
| Lost passkey or hardware key | SSH into the daemon host, revoke the lost credential with `shisad 2fa revoke`, then enroll a replacement |
| Lost signer key | Use your KMS provider's break-glass/recovery process, then revoke and re-register the key in shisad |
| Lost all credentials + host access | Restore from backups or re-provision — there is no special in-band recovery ceremony for this case |

There are no implicit downgrades. If a required factor is unavailable and
policy does not allow a fallback level, the action is denied.

---

## Environment Variables

### Required (to enable a feature)

| Variable | What it enables |
|---|---|
| `SHISAD_APPROVAL_ORIGIN` | Browser WebAuthn ceremony surface (passkey registration and approval links). Without this, browser WebAuthn is unavailable. |
| `SHISAD_SIGNER_KMS_URL` | L3 signer backend. Without this, `kms` approvals are unavailable and KMS-requiring policies fail closed. |

### Optional (auto-derived or tuning)

| Variable | Default behavior when unset |
|---|---|
| `SHISAD_APPROVAL_RP_ID` | Derived from `SHISAD_APPROVAL_ORIGIN` hostname |
| `SHISAD_APPROVAL_BIND_HOST` | `127.0.0.1` (or derived from origin for loopback) |
| `SHISAD_APPROVAL_BIND_PORT` | `8787` (or derived from origin for loopback) |
| `SHISAD_APPROVAL_LINK_TTL_SECONDS` | Default link expiry for registration and approval links |
| `SHISAD_APPROVAL_RATE_LIMIT_WINDOW_SECONDS` | Default rate-limit window for ceremony POST attempts |
| `SHISAD_APPROVAL_RATE_LIMIT_MAX_ATTEMPTS` | Default max attempts per rate-limit window |
| `SHISAD_SIGNER_KMS_BEARER_TOKEN` | No bearer token sent to KMS endpoint |
| `SHISAD_SECURITY_APPROVAL_FACTOR_STORE_PATH` | `SHISAD_DATA_DIR/approval-factors.json` |
| `SHISAD_SOCKET_PATH` | Default daemon control socket path |

See [ENV-VARS.md](ENV-VARS.md) for the complete reference.

---

## Storage and Audit

### Credential storage

- Approval factors (TOTP secrets, passkey public keys, helper credentials) and
  signer public keys are stored in a daemon-owned JSON file.
- Default location: `SHISAD_DATA_DIR/approval-factors.json`
- Override with: `SHISAD_SECURITY_APPROVAL_FACTOR_STORE_PATH`
- **Not encrypted at rest** in v0.6.3. Protect with filesystem permissions.

### What the audit trail records

Every approval records:

| Field | Description |
|---|---|
| Level | Which approval level was satisfied (`software`, `reauthenticated`, etc.) |
| Method | Which backend handled it (`totp`, `webauthn`, `local_fido2`, `kms`, etc.) |
| Approver principal | Who approved (label from enrollment) |
| Credential ID | Which specific credential was used |
| Binding scope | What the proof commits to (`none`, `action_digest`, `approval_envelope`, `full_intent`) |
| Review surface | Where the operator reviewed the action (`host_rendered`, `browser_rendered`, `provider_ui`, etc.) |
| Third-party verifiable | Whether the proof can be verified outside shisad |
| Fallback used | Whether a lower-than-requested level was accepted via explicit fallback policy |
| Evidence hash | Tamper-detection hash over the full evidence payload |

For L3+ signed approvals, the audit trail also includes:

| Field | Description |
|---|---|
| Intent envelope hash | Hash of the canonical `IntentEnvelope` that was signed |
| Signature | The cryptographic signature returned by the signer |
| Signer key ID | Which registered key produced the signature |
| Blind sign detected | Whether the signing device could not render a human-readable action summary |

---

## Troubleshooting

| Error | Meaning | Fix |
|---|---|---|
| `approval_origin_not_configured` | Browser WebAuthn was requested but `SHISAD_APPROVAL_ORIGIN` is not set | Set the env var, or use the local helper / TOTP instead |
| `local_helper_unavailable` | Local-helper backend not active in current daemon mode | Check daemon config; the helper backend activates when no approval origin is set |
| `missing_decision_nonce` | CLI could not auto-resolve the nonce from pending state | Run `shisad action pending` and pass `--nonce` explicitly |
| `confirmation_method_mismatch` | The proof you submitted does not match the pending action's required backend | Check `shisad action pending` for the required method |
| `confirmation_method_locked_out` | Too many failed attempts | Wait for the `retry_after_seconds` period to expire |
| `signer_backend_invalid_response` | The KMS endpoint returned a malformed or invalid response | Check KMS endpoint logs; the daemon fails closed on invalid responses |

---

## Not Yet Shipped

- **L4 trusted-display authorization:** Consumer Ledger clear-signing and
  other trusted-display hardware flows. The protocol and policy language are
  ready; device integration is follow-on. See the developer section below for
  integration details.
- **Push-notification approvals:** Planned as a future L1 method.
- **M-of-N multi-approver / quorum:** The schema supports multiple principals
  and credentials, but quorum enforcement is not yet built. Environments that
  need quorum today should use an Enterprise KMS that enforces it on their
  side — shisad sees one L3 signature.
- **At-rest encryption for credential store:** The approval-factor store is
  currently plaintext JSON. At-rest encryption is follow-on.
- **TOTP via approval web page:** planned follow-on.

## Shipped in v0.6.3

- **TOTP via chat reply:** shipped for trusted chat / command replies.
- **QR code for TOTP enrollment:** shipped as a best-effort terminal rendering
  path with the raw `otpauth://` URI preserved as fallback.

---

## Developer Reference: Integrating an L3/L4 Signer Backend

This section is for developers building signer backends — for example,
integrating a hardware wallet (Ledger), HSM, or custom KMS with shisad's
approval protocol. It describes the protocol contracts, data structures, and
verification flow that a backend must implement.

### Architecture overview

```
Agent proposes action
    │
    ▼
PEP evaluates policy → required level: signed_authorization
    │
    ▼
Daemon builds IntentEnvelope (canonical signable payload)
    │
    ▼
Daemon sends IntentEnvelope to signer backend
    │
    ├── Enterprise KMS: HTTP POST to endpoint, human approval in provider UI
    ├── Consumer Ledger: display on trusted screen, user physically confirms
    └── Custom backend: your implementation here
    │
    ▼
Backend returns signature + metadata
    │
    ▼
Daemon verifies signature against registered public key
    │
    ├── Valid → execute action, record in audit trail
    ├── Invalid → reject, log verification failure
    └── Timeout → reject, log expiry (fail-closed)
```

### The `IntentEnvelope` (what gets signed)

The `IntentEnvelope` is a canonical, deterministic description of the action
the operator is approving. The signer backend signs this structure (or its
hash). It is a Pydantic model with `frozen=True`.

**Fields:**

| Field | Type | Description |
|---|---|---|
| `schema_version` | `str` | Always `"shisad.intent.v1"` |
| `intent_id` | `str` | Unique ID for this intent (same as `confirmation_id`) |
| `agent_id` | `str` | Daemon instance fingerprint |
| `workspace_id` | `str` | Workspace UUID |
| `session_id` | `str` | Session UUID |
| `created_at` | `datetime` | When the intent was created (UTC) |
| `expires_at` | `datetime \| None` | Expiry deadline (UTC) |
| `action` | `IntentAction` | The action being approved (see below) |
| `policy_context` | `IntentPolicyContext` | Why this approval is required |
| `nonce` | `str` | Base64url-encoded 32-byte random nonce |

**`IntentAction` sub-structure:**

| Field | Type | Description |
|---|---|---|
| `tool` | `str` | Canonical dotted tool ID (e.g., `"deploy.production"`) |
| `display_summary` | `str` | Human-readable action summary (for display only, not a security claim) |
| `parameters` | `dict[str, Any]` | Normalized tool arguments |
| `destinations` | `list[str]` | Resolved sink set (hosts, domains, paths) |

**`IntentPolicyContext` sub-structure:**

| Field | Type | Description |
|---|---|---|
| `required_level` | `ConfirmationLevel` | The level policy requires |
| `confirmation_reason` | `str` | Why confirmation is required |
| `matched_rule` | `str` | Which policy rule triggered the requirement |
| `action_digest` | `str` | SHA-256 hash of the canonical action description |

### The `ApprovalEnvelope` (universal approval context)

Every approval method (including TOTP and WebAuthn) binds to an
`ApprovalEnvelope`. For L3+ backends, the `ApprovalEnvelope` references the
full `IntentEnvelope` via `intent_envelope_hash`. Signers sign the
`IntentEnvelope`; challenge/response methods bind to the
`approval_envelope_hash`.

**Key fields:**

| Field | Type | Description |
|---|---|---|
| `schema_version` | `str` | `"shisad.approval.v1"` |
| `approval_id` | `str` | Unique approval ID |
| `pending_action_id` | `str` | The pending action this approval is for |
| `required_level` | `ConfirmationLevel` | Required approval level |
| `action_digest` | `str` | `sha256(canonical_json(action_digest_payload))` |
| `intent_envelope_hash` | `str \| None` | Hash of the `IntentEnvelope` (set for L3+) |
| `allowed_principals` | `list[str]` | Which principals can satisfy this approval |
| `allowed_credentials` | `list[str]` | Which credentials can satisfy this approval |
| `nonce` | `str` | Base64url-encoded 32-byte random nonce |
| `action_summary` | `str` | Human-readable summary (excluded from hash computation) |

**Hash computation:**

- `approval_envelope_hash = sha256(canonical_json(envelope_without_action_summary))`
- `action_summary` is excluded so display text cannot change the
  cryptographic binding.

### Canonical JSON and hashing

All hashing uses SHA-256 over canonical JSON:

- Dictionary keys are sorted recursively
- Datetimes are normalized to ISO 8601 UTC with `"Z"` suffix
- Serialized with `separators=(",", ":")` (compact, no whitespace)
- `ensure_ascii=False`, `allow_nan=False`

This is functionally similar to JCS (JSON Canonicalization Scheme) but uses
Python's `json.dumps(sort_keys=True)` with custom normalization.

### Signer backend protocol

A signer backend implements four methods:

| Method | Purpose |
|---|---|
| `list_registered_keys(user_id, include_revoked)` → `list[SignerKeyInfo]` | List keys registered for a user |
| `request_signature(envelope, signer_key_id, timeout)` → `SignatureResult` | Send the `IntentEnvelope` to the signer and get a signature back |
| `verify_signature(envelope, signature, signer_key)` → `bool` | Verify a signature against the registered public key |
| `record_key_use(signer_key_id, when)` | Record that a key was used (for audit/rotation tracking) |

### KMS HTTP signing contract

The shipped `EnterpriseKmsSignerBackend` uses a simple HTTP POST contract. If
you are building a KMS-compatible endpoint, implement this:

**Request** (POST to your endpoint):

```json
{
  "schema_version": "shisad.sign_request.v1",
  "backend": "kms",
  "signer_key_id": "kms:finance-primary",
  "intent_envelope_hash": "sha256:...",
  "intent_envelope": { "...full IntentEnvelope as JSON..." },
  "timeout_seconds": 300
}
```

**Response:**

```json
{
  "status": "approved",
  "signer_key_id": "kms:finance-primary",
  "signature": "base64:...",
  "signed_at": "2026-04-08T12:00:00Z",
  "review_surface": "provider_ui",
  "blind_sign_detected": false,
  "reason": ""
}
```

**`status` values:** `"approved"`, `"rejected"`, `"expired"`, `"error"`

**Signature format:** Base64-encoded raw signature bytes, prefixed with
`"base64:"`.

**Supported algorithms:**

- **Ed25519:** sign the canonical JSON bytes of the `IntentEnvelope`
- **ECDSA secp256k1:** sign with SHA-256 digest over the canonical JSON bytes

The daemon verifies the returned signature locally against the registered
public key. The KMS cannot forge approvals — it can only deny service or
report an error.

### Capability claims

Backends advertise their capabilities via `ConfirmationCapabilities`:

| Capability | Type | Meaning |
|---|---|---|
| `principal_binding` | `bool` | Evidence can be tied to a specific registered operator |
| `approval_binding` | `bool` | Proof is bound to the approval envelope |
| `action_digest_binding` | `bool` | Proof commits to the action digest |
| `full_intent_signature` | `bool` | Proof signs the full `IntentEnvelope` |
| `trusted_display` | `bool` | The operator reviewed the action on an independent hardware display |
| `third_party_verifiable` | `bool` | The proof can be verified outside shisad |
| `blind_sign_detection` | `bool` | The backend can detect when the device signed opaque bytes |

Policy rules can require specific capabilities:

```yaml
require_capabilities:
  principal_binding: true
  full_intent_signature: true
  third_party_verifiable: true
```

### Implementing an L4 trusted-display backend

L4 (`trusted_display_authorization`) is L3 plus the guarantee that the
operator reviewed the action on an independent tamper-resistant display (e.g.,
Ledger Stax/Flex touchscreen, GridPlus Lattice1).

To qualify for L4, a backend must:

1. **Sign the full `IntentEnvelope`** (not just a hash or opaque bytes)
2. **Render a human-readable action summary on a trusted device display**
   (not host-rendered, not browser-rendered)
3. **Report `review_surface: "trusted_device_display"`** honestly based on
   what actually happened for this specific signing request
4. **Set `blind_sign_detected: true`** when the device could not render the
   action (e.g., unsupported transaction type, device fell back to raw hex)
5. **Advertise `trusted_display: true`** in its capability claims

**Important:** Blind signing (device signs opaque bytes the operator cannot
read) is *not* L4, even if the device is capable of clear-signing in other
contexts. The `review_surface` must reflect what happened for *this specific
action*, not the device's general capabilities.

**Review surface spectrum** (for reference when classifying your backend):

| Review quality | Example | Honest classification |
|---|---|---|
| No device display | YubiKey PIV, cloud KMS API-only | `opaque_device` or `provider_ui` |
| Raw hex / opaque digest | Ledger with unsupported contract | `opaque_device`, `blind_sign_detected: true` |
| Decoded fields on small screen | Ledger Nano S+ clear-signing | `trusted_device_display` (but note scroll-through UX) |
| Full summary on large screen | Ledger Stax/Flex, GridPlus Lattice1 | `trusted_device_display` |
| Provider web UI | Enterprise KMS approval dashboard | `provider_ui` (not L4 — runs in a browser) |

### Confirmation evidence structure

After verification, the backend produces a `ConfirmationEvidence` record that
the daemon stores in the audit trail. Key fields for signer backends:

| Field | Description |
|---|---|
| `level` | The confirmation level that was satisfied |
| `method` | Backend method name (e.g., `"kms"`) |
| `binding_scope` | `"full_intent"` for L3+ signers |
| `review_surface` | What the operator actually saw |
| `third_party_verifiable` | `true` for signature-based proofs |
| `intent_envelope_hash` | Hash of the signed intent |
| `signature` | The cryptographic signature |
| `signer_key_id` | Which key signed |
| `blind_sign_detected` | Whether this was a blind sign |
| `evidence_hash` | Tamper-detection hash over the full evidence |

---

## Further Reading

- [ENV-VARS.md](ENV-VARS.md) — complete environment variable reference
- [SECURITY.md](SECURITY.md) — overall security architecture
- [ROADMAP.md](ROADMAP.md) — release timeline and milestones
