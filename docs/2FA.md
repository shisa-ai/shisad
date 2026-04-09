# Multi-Factor Approval (2FA)

This page explains how approval factors work in `shisad` as shipped in v0.6.2:
what is available now, how to set it up, and which settings matter.

`shisad` and `shisactl` are the same CLI entrypoint. This doc uses `shisad`
for consistency.

## What Is Included in v0.6.2

2FA is **opt-in**. If you do not enroll any factor, approvals use the standard
L0 software confirmation flow.

| Level | Policy value | What it means | Available now |
|---|---|---|---|
| L0 | `software` | Basic click/confirm approval | Yes |
| L1 | `reauthenticated` | Operator proves presence (TOTP or recovery code) | Yes |
| L2 | `bound_approval` | Approval is cryptographically bound to a specific pending action | Yes |
| L3 | `signed_authorization` | Registered signer key signs canonical intent | Yes |
| L4 | `trusted_display_authorization` | L3 + independent trusted-device display review | Not shipped yet |

## Before You Start

- Ensure the daemon is running and your CLI can reach the control socket.
- Pending approvals are visible with:

```bash
shisad action pending
```

- Confirmations are submitted with:

```bash
shisad action confirm <CONFIRMATION_ID>
```

`action confirm` tries to auto-resolve the decision nonce from pending state.
If it cannot, pass `--nonce` from `action pending` output.

---

## L1: TOTP (Authenticator Apps)

TOTP works with apps like Google Authenticator, Authy, 1Password, or similar.

### Enroll

```bash
shisad 2fa register --method totp --user alice --name "phone-authenticator"
```

The CLI prints:

- a TOTP secret,
- an `otpauth://...` URI,
- and then prompts for a verification code.

If verification succeeds, it also prints **8 single-use recovery codes**.
Store those recovery codes offline. They are shown at enrollment time.

### Use for an approval

```bash
shisad action confirm <CONFIRMATION_ID> --totp-code 123456
```

or with a recovery code:

```bash
shisad action confirm <CONFIRMATION_ID> --recovery-code XXXX-XXXX
```

### Important behavior

- TOTP is L1 (`reauthenticated`), not L2/L3.
- TOTP codes are 30-second codes with ±1 step tolerance.
- A TOTP code cannot be reused within its valid window.
- Recovery codes are one-time use.

Do not paste TOTP/recovery codes into chat transcripts.

---

## L2: Passkey in Browser (WebAuthn)

Use this when operators can open an approval URL in a browser.

### Required settings

Set `SHISAD_APPROVAL_ORIGIN` to the origin operators will use.

- Non-loopback origins must be `https://...`.
- Loopback `http://127.0.0.1...` / `http://localhost...` is allowed for local dev/tests.
- Use origin form only: `scheme://host[:port]` (no path/query/fragment).

Example:

```bash
export SHISAD_APPROVAL_ORIGIN="https://approve.example.com"
```

Optional helper to print env + reverse proxy guidance:

```bash
shisad approval setup --provider caddy
# or
shisad approval setup --provider tailscale
```

`approval setup` expects an `https` origin.

### Enroll a passkey

```bash
shisad 2fa register --method webauthn --user alice --name "yubikey-5-nfc"
```

This opens (or prints) a registration URL and waits for registration completion.

### Approve a pending L2 action

```bash
shisad action confirm <CONFIRMATION_ID>
```

For WebAuthn-pending actions, the CLI prints an approval URL, optionally opens
the browser, and waits for completion.

If `SHISAD_APPROVAL_ORIGIN` is unset, browser WebAuthn is unavailable.

---

## L2: SSH/Private-Only Passkey (`shisad-approver`)

Use the local helper when browser WebAuthn is not practical (for example,
SSH-only/private deployment).

### Important current behavior

In v0.6.2, browser WebAuthn and local-helper (`local_fido2`) are alternate L2
backends. Practically:

- with `SHISAD_APPROVAL_ORIGIN` configured, browser WebAuthn is used;
- without it, local-helper L2 is available.

### Enroll helper credential

```bash
shisad-approver register \
  --ssh-target user@host \
  --remote-socket /run/shisad/control.sock \
  --user alice \
  --name "laptop-yubikey"
```

### Run helper to process pending local-helper approvals

```bash
shisad-approver run \
  --ssh-target user@host \
  --remote-socket /run/shisad/control.sock
```

If helper runs on the daemon host, use `--socket-path` instead of SSH flags.
When using SSH forwarding, `--remote-socket` should match the daemon's
`SHISAD_SOCKET_PATH`.

### Credential compatibility note

Browser WebAuthn credentials and local-helper credentials are separate pools
with different rpIds. They are not interchangeable.

---

## L3: Signer/KMS Authorization

Use this when approvals must be signed and externally verifiable.

### Required settings

```bash
export SHISAD_SIGNER_KMS_URL="https://kms.example.com/sign"
export SHISAD_SIGNER_KMS_BEARER_TOKEN="..."   # optional
```

### Register signer public key

```bash
shisad signer register \
  --user alice \
  --key-id kms:finance-primary \
  --public-key /path/to/public-key.pem
```

List or revoke keys:

```bash
shisad signer list
shisad signer revoke --key-id kms:finance-primary
```

If `SHISAD_SIGNER_KMS_URL` is unset, `kms` approvals are unavailable and
policies requiring them fail closed.

---

## Policy Examples (with Plain Explanations)

Approval policy is per tool under `tools.<tool_name>.confirmation`.

### L0 software approval

```yaml
tools:
  shell.exec:
    require_confirmation: true
```

### L1 TOTP/recovery-code approval

```yaml
tools:
  git.status:
    confirmation:
      level: reauthenticated
      timeout_seconds: 300
```

### L2 passkey-only approval

```yaml
tools:
  shell.exec:
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

### L2 with explicit L1 fallback

```yaml
tools:
  shell.exec:
    confirmation:
      level: bound_approval
      fallback:
        mode: allow_levels
        allow_levels: [reauthenticated]
```

`allow_levels` is level-based fallback. If you restrict `methods`, include a
method that exists at the fallback level (or leave `methods` empty), otherwise
fallback may not route.

### L3 signer/KMS approval

```yaml
tools:
  shell.exec:
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

### Risk-based escalation

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

## Credential Management and Recovery

List enrolled factors:

```bash
shisad 2fa list
shisad 2fa list --method totp
shisad 2fa list --user alice
```

Revoke:

```bash
shisad 2fa revoke --method totp --user alice
shisad 2fa revoke --method webauthn --user alice --credential-id <ID>
shisad 2fa revoke --method local_fido2 --user alice --credential-id <ID>
```

Recovery guidance:

- Lost TOTP device: use a recovery code, then revoke and re-enroll.
- Lost passkey/helper key: revoke credential from host access, then re-enroll.
- Lost high-tier signer credentials: recover via your normal host/KMS break-glass
  process (no separate in-band recovery flow in v0.6.2).

---

## Environment Variables You Actually Need

| Variable | What it controls |
|---|---|
| `SHISAD_APPROVAL_ORIGIN` | Enables browser WebAuthn ceremony surface (registration + approval links). |
| `SHISAD_APPROVAL_RP_ID` | Optional WebAuthn rpId override (defaults to origin hostname). |
| `SHISAD_APPROVAL_BIND_HOST` | Daemon listener host for ceremony pages. |
| `SHISAD_APPROVAL_BIND_PORT` | Daemon listener port for ceremony pages. |
| `SHISAD_APPROVAL_LINK_TTL_SECONDS` | Registration/approval link expiry. |
| `SHISAD_APPROVAL_RATE_LIMIT_WINDOW_SECONDS` | POST rate-limit window for ceremony tokens. |
| `SHISAD_APPROVAL_RATE_LIMIT_MAX_ATTEMPTS` | Max POST attempts per rate-limit window. |
| `SHISAD_SIGNER_KMS_URL` | L3 signer backend endpoint (`kms` method). |
| `SHISAD_SIGNER_KMS_BEARER_TOKEN` | Optional bearer token for signer endpoint. |
| `SHISAD_SOCKET_PATH` | Daemon control socket path (used by CLI and helper forwarding). |
| `SHISAD_SECURITY_APPROVAL_FACTOR_STORE_PATH` | Optional override for factor/signer state file location. |
| `SHISAD_DATA_DIR` | Base data dir; default factor store lives under this dir when no explicit store override is set. |

---

## Storage and Audit Reality (Current Release)

- Approval factors and signer keys are stored in daemon-owned JSON state.
- Default location is `SHISAD_DATA_DIR/approval-factors.json` unless
  `SHISAD_SECURITY_APPROVAL_FACTOR_STORE_PATH` is explicitly set.
- This store is **not encrypted at rest** in v0.6.2.

Approval audit includes:

- level + method,
- approver principal + credential id,
- binding scope + review surface,
- fallback usage,
- evidence hash,
- and for signed approvals, intent hash/signature/signer key id.

---

## Troubleshooting

- `approval_origin_not_configured`: browser WebAuthn requested, but no approval origin is configured.
- `local_helper_unavailable`: local-helper backend not active in current daemon mode.
- `missing_decision_nonce`: run `shisad action pending` and pass `--nonce`, or ensure CLI can read pending state.
- `confirmation_method_mismatch`: provided proof type does not match pending backend.
- `confirmation_method_locked_out`: too many failed attempts; wait for `retry_after_seconds`.

---

## Not Yet Shipped

- L4 trusted-display authorization device integrations.
- Push-notification approval methods.
- M-of-N multi-approver/quorum enforcement in-core.
- At-rest encryption for approval-factor/recovery-code store.

## Further Reading

- [ENV-VARS.md](ENV-VARS.md)
- [SECURITY.md](SECURITY.md)
- [ROADMAP.md](ROADMAP.md)
