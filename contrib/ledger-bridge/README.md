# shisad Ledger Bridge

HTTP bridge service that connects shisad's L4 trusted-display approval system to Ledger hardware devices via the [Device Management Kit (DMK)](https://github.com/LedgerHQ/device-sdk-ts).

## How It Works

```
shisad daemon  ──HTTP POST──>  ledger-bridge  ──USB/DMK──>  Ledger Device
               (IntentEnvelope)               (signTypedData / EIP-712)
               <──SignatureResult──            <──ECDSA sig──
```

The bridge implements the same sign-request/response contract as shisad's KMS backend. When the daemon needs an L4 approval:

1. The daemon POSTs an `IntentEnvelope` plus its canonical `intent_envelope_hash` to the bridge
2. The bridge builds EIP-712 typed data with readable action fields and the full-intent hash
3. The bridge connects to the Ledger and calls `signTypedData`
4. The user reviews the action on the device display and confirms
5. The bridge returns the ECDSA signature to the daemon

## Setup

```bash
cd contrib/ledger-bridge
npm install
```

## Usage

### 1. Extract your Ledger's public key

```bash
npx tsx src/extract-key.ts > pubkey.pem
```

### 2. Register the key with shisad

```bash
shisad signer register \
  --backend ledger \
  --user alice \
  --key-id ledger:stax-1 \
  --public-key pubkey.pem
```

### 3. Start the bridge

```bash
export SHISAD_LEDGER_BRIDGE_BEARER_TOKEN="$(openssl rand -hex 32)"
npx tsx src/server.ts --port 9090
```

### 4. Configure shisad

```bash
export SHISAD_SIGNER_LEDGER_URL="http://127.0.0.1:9090/sign"
export SHISAD_SIGNER_LEDGER_BEARER_TOKEN="$SHISAD_LEDGER_BRIDGE_BEARER_TOKEN"
```

### 5. Set policy (optional)

```yaml
tools:
  "deploy.production":
    confirmation:
      level: trusted_display_authorization
      methods: [ledger]
      require_capabilities:
        trusted_display: true
```

## Options

### Server

| Flag | Default | Description |
|------|---------|-------------|
| `--port` | `9090` | HTTP listen port |
| `--derivation-path` | `44'/60'/0'/0/0` | Ethereum derivation path |
| `--bearer-token` | `SHISAD_LEDGER_BRIDGE_BEARER_TOKEN` | Optional token required as `Authorization: Bearer ...` on `/sign` and `/extract-key` |

### Key Extraction

| Flag | Default | Description |
|------|---------|-------------|
| `--derivation-path` | `44'/60'/0'/0/0` | Ethereum derivation path |

## Supported Devices

| Device | Screen | Review Surface |
|--------|--------|---------------|
| Ledger Stax | Large touchscreen | `trusted_device_display` |
| Ledger Flex | Large touchscreen | `trusted_device_display` |
| Ledger Nano X | Small OLED (scroll) | `opaque_device` |
| Ledger Nano S Plus | Small OLED (scroll) | `opaque_device` |
| Unknown model | Unknown | `opaque_device` |

## Signing Mechanism

The bridge uses the Ethereum app's `signTypedData` which:
- Renders EIP-712 structured fields on the device display
- Includes the canonical `intent_envelope_hash` in the signed typed data, binding the signature to the full daemon-side `IntentEnvelope`
- Signs with ECDSA secp256k1 over the EIP-712 digest
- Returns `(r, s, v)` which the bridge DER-encodes for shisad

The daemon verifies the signature using the `eip712` signing scheme registered with the key. Stax/Flex models are reported as `trusted_device_display`; Nano and unknown models are reported as `opaque_device` with `blind_sign_detected: true`, which downgrades the approval below L4.
