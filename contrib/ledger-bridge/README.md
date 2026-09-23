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
4. The user reviews the typed fields and confirms on the device. Generic EIP-712 review can still show a blind-signing warning, including on Stax. The current bridge classifies review metadata by model; it does not detect that warning per signing request.
5. The bridge returns the ECDSA signature to the daemon

## Setup

```bash
cd contrib/ledger-bridge
npm install
```

## Usage

### 1. Extract your Ledger's public key

```bash
npm run --silent extract-key -- > pubkey.pem
```

Run `npm install` first so `tsx` resolves from this package's local
dependencies. Avoid redirecting `npx tsx ...` directly into `pubkey.pem`;
interactive package-manager prompts can corrupt the PEM output.

### 2. Register the key with shisad

Replace the address placeholder below with the full address you verified on
the Ledger screen during extraction. The daemon compares it with the address
derived from the PEM and refuses a mismatch before saving the signer. This is
account matching, not device attestation. Omitting the option retains manual
PEM-only enrollment and reports that ownership was not checked.

```bash
shisad signer register \
  --backend ledger \
  --user alice \
  --key-id ledger:stax-1 \
  --public-key pubkey.pem \
  --expected-address '<address verified on the device>'
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
| Ledger Nano X | Small OLED (scroll) | `opaque_device` | Linux: verified round-trip in `v0.6.7.1` (maintainer test, Ethereum app 1.22.0). macOS/Windows: not maintainer-tested yet. |
| Ledger Nano S Plus | Small OLED (scroll) | `opaque_device` | Unverified; awaiting Ledger compatibility matrix |
| Unknown model | Unknown | `opaque_device` | Unverified |

This table shows the bridge's runtime classification for device models it
reports. It is not a maintainer-validated hardware and firmware support
matrix. The Ledger-validated device, firmware, and Ethereum-app compatibility
list is still pending from Ledger.

### Linux-specific note for Nano X / Nano S Plus

Some Ledger devices expose multiple HID interfaces on USB (APDU, FIDO/U2F,
and sometimes a generic interface). Ledger's upstream Node HID transport
filters to the APDU interface on macOS and Windows only — on Linux it
accepts all interfaces, which can cause the bridge to latch onto the
FIDO interface and hang on the first APDU. The bridge applies the same
APDU-interface filter on Linux as a workaround (see
`src/linux-hid-filter.ts`). The Nano X Linux round-trip was verified by
the maintainer in `v0.6.7.1` against Ethereum app 1.22.0; Nano S Plus
is expected to behave the same way but has not been maintainer-tested.

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

## Clear-signing metadata

The [ERC-7730 descriptor](clear-signing/eip712-shisad.json) describes the existing
EIP-712 domain and all signed leaf fields, including the full canonical intent
hash and nonce. It is a submission candidate, not installed device metadata.
Adding this file locally does not remove a blind-signing warning. It passes the
upstream JSON schema, but the current `erc7730 lint` tool requires a deployment
list that this off-chain domain does not have. Ledger must resolve that
compatibility question before registry submission.

The Ethereum signer can use a Ledger partner origin token through
`SHISAD_LEDGER_ORIGIN_TOKEN`. Set it in the bridge process environment and keep
it out of version control. It is separate from the bridge HTTP bearer token.
The SDK's default context module resolves Ledger-provided metadata; the bridge
does not inject or trust arbitrary local descriptor files.

Before claiming warning-free Clear Signing:

1. Confirm with Ledger that the off-chain `shisad` domain (version `1`, chain
   ID `0`, no verifying contract) is supported. The installed SDK substitutes
   the zero address when looking up metadata for a missing verifying contract.
   Do not invent a deployed contract or change the signed domain to satisfy a
   registry entry.
2. Validate the descriptor with `erc7730 lint`, then follow Ledger's
   [submission procedure](https://developers.ledger.com/docs/clear-signing/for-dapps/validate-submit)
   and obtain the required origin token through its
   [integration program](https://developers.ledger.com/docs/clear-signing/for-wallets).
3. After the matching signed metadata is available to the SDK, verify on a
   physical device that every action field is readable, no blind-signing warning
   appears, and approval/rejection still binds the canonical intent.

The existing `trusted_device_display` / `blind_sign_detected` values for Stax
and Flex are model-based classifications, not evidence that ERC-7730 metadata
was used. Do not use them to claim warning-free signing. Descriptor publication,
Ledger support for this off-chain domain, and device validation remain required.
