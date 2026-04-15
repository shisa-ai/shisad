# shisad Ledger Bridge

HTTP bridge service that connects shisad's L4 trusted-display approval system to Ledger hardware devices via the [Device Management Kit (DMK)](https://github.com/LedgerHQ/device-sdk-ts).

## How It Works

```
shisad daemon  ──HTTP POST──>  ledger-bridge  ──USB/DMK──>  Ledger Device
               (IntentEnvelope)               (signPersonalMessage)
               <──SignatureResult──            <──ECDSA sig──
```

The bridge implements the same sign-request/response contract as shisad's KMS backend. When the daemon needs an L4 approval:

1. The daemon POSTs an `IntentEnvelope` to the bridge
2. The bridge formats the action summary for the device display
3. The bridge connects to the Ledger and calls `signPersonalMessage`
4. The user reviews the action on the device's trusted display and confirms
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
npx tsx src/server.ts --port 9090
```

### 4. Configure shisad

```bash
export SHISAD_SIGNER_LEDGER_URL="http://127.0.0.1:9090/sign"
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

### Key Extraction

| Flag | Default | Description |
|------|---------|-------------|
| `--derivation-path` | `44'/60'/0'/0/0` | Ethereum derivation path |

## Supported Devices

| Device | Screen | Review Surface |
|--------|--------|---------------|
| Ledger Stax | Large touchscreen | `trusted_device_display` |
| Ledger Flex | Large touchscreen | `trusted_device_display` |
| Ledger Nano X | Small OLED (scroll) | `trusted_device_display` |
| Ledger Nano S Plus | Small OLED (scroll) | `trusted_device_display` |

## Signing Mechanism

The bridge uses the Ethereum app's `signPersonalMessage` which:
- Renders the formatted action summary on the device's trusted display
- Signs with ECDSA secp256k1: `keccak256("\x19Ethereum Signed Message:\n" + len + msg)`
- Returns `(r, s, v)` which the bridge DER-encodes for shisad

The daemon verifies the signature using the `eth_personal_sign` signing scheme registered with the key.
