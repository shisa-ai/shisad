# shisad Ledger Bridge

HTTP bridge service that connects shisad's signer-backend contract to Ledger
hardware devices via the [Device Management Kit
(DMK)](https://github.com/LedgerHQ/device-sdk-ts).

## How It Works

```
shisad daemon  ──HTTP POST──>  ledger-bridge  ──USB/DMK──>  Ledger Device
               (IntentEnvelope)               (signTypedData / EIP-712)
               <──SignatureResult──            <──ECDSA sig──
```

The bridge implements the same sign-request/response contract as
shisad's KMS backend. When the daemon needs a Ledger-backed signature:

1. The daemon POSTs an `IntentEnvelope` plus its canonical `intent_envelope_hash` to the bridge
2. The bridge builds EIP-712 typed data with readable action fields and the full-intent hash
3. The reference bridge connects to the Ledger over USB HID and calls `signTypedData`
4. If the device path exposes readable review metadata, the user reviews the action on the device display and confirms; if the device reports an opaque or blind-signing path, shisad records that lower-trust evidence instead of treating it as L4
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

## Reported Model Classification

| Device | Screen | Review Surface | Maintainer verification |
|--------|--------|----------------|-------------------------|
| Ledger Stax | Large touchscreen | `trusted_device_display` | Pending device-attached verification |
| Ledger Flex | Large touchscreen | `trusted_device_display` | Pending device-attached verification |
| Ledger Nano X | Small OLED (scroll) | `opaque_device` | Unverified; maintainer-side DMK 1.2.0 + Linux round-trip currently hangs |
| Ledger Nano S Plus | Small OLED (scroll) | `opaque_device` | Unverified; awaiting Ledger compatibility matrix |
| Unknown model | Unknown | `opaque_device` | Unverified |

This table shows the bridge's runtime classification for device models it
reports. It is not a maintainer-validated hardware and firmware support
matrix. `v0.6.7` ships before that matrix is published; the current
follow-up is to request Ledger's validated device, firmware, and Ethereum-app
list and publish it in `v0.6.7.1`.

## Signing Mechanism

The bridge uses the Ethereum app's `signTypedData` which:
- Can render EIP-712 structured fields on the device display when the device/app path exposes readable review metadata
- Includes the canonical `intent_envelope_hash` in the signed typed data, binding the signature to the full daemon-side `IntentEnvelope`
- Signs with ECDSA secp256k1 over the EIP-712 digest
- Returns `(r, s, v)` which the bridge DER-encodes for shisad

The daemon verifies the signature using the `eip712` signing scheme
registered with the key. Stax/Flex models are reported as
`trusted_device_display`; Nano and unknown models are reported as
`opaque_device` with `blind_sign_detected: true`, which downgrades the
approval below L4.

The reference bridge currently uses Ledger's Node HID transport
(`@ledgerhq/device-transport-kit-node-hid`). Bluetooth is not
implemented in this bridge today.
