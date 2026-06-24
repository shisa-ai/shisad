# Ledger Bridge for Remote shisad

Use this runbook when the shisad daemon runs on a remote host but the Ledger
hardware wallet is plugged into a local operator workstation. The reference
bridge must stay close to the USB device; the remote daemon reaches it through
a private path and verifies returned signatures against the registered public
key.

## Topology

```text
remote shisad daemon
  -> authenticated signer request over private HTTP path
local Ledger bridge
  -> USB HID
Ledger device review/sign
  -> ECDSA signature over EIP-712 typed data
local Ledger bridge
  -> signature response
remote shisad daemon
  -> verify signature against registered public key
```

The bearer token authenticates the daemon-to-bridge HTTP request. It does not
replace the daemon's signature verification, and it is not a reason to expose
the bridge on the public internet. The daemon accepts an approval only when the
signature verifies against the registered public key for the requested signer
key ID.

## Security Rules

- Do not expose the Ledger bridge publicly. It is a USB signer bridge and
  should be reachable only on loopback, over a reverse SSH tunnel, or through a
  private network boundary you control.
- Prefer the default bridge bind address, `127.0.0.1`. The reference bridge
  listens on loopback only.
- Set a high-entropy bearer token on both sides. Treat it like an operational
  secret.
- For any non-loopback private network deployment, put the bridge behind a
  transport boundary that protects the bearer token in transit, such as SSH,
  WireGuard, Tailscale, or HTTPS from a trusted local proxy.
- Register the Ledger public key with the daemon before relying on the bridge
  for approvals. The bridge can return signatures; only the daemon-side
  registered public key decides whether those signatures authorize an action.

## Start the Local Ledger Bridge

On the workstation that has the Ledger plugged in:

```bash
cd contrib/ledger-bridge
npm install
export SHISAD_LEDGER_BRIDGE_BEARER_TOKEN="$(openssl rand -hex 32)"
npx tsx src/server.ts --port 9090
```

The bridge prints:

```text
shisad-ledger-bridge listening on http://127.0.0.1:9090/sign
```

Leave the bridge bound to loopback. If you need a different derivation path,
pass it explicitly and use the same path when extracting the public key:

```bash
npx tsx src/server.ts --port 9090 --derivation-path "44'/60'/0'/0/0"
```

You can also pass the token as a flag:

```bash
npx tsx src/server.ts --port 9090 --bearer-token "$SHISAD_LEDGER_BRIDGE_BEARER_TOKEN"
```

## Connect Remote shisad Safely

### Reverse SSH Tunnel

Run this from the local workstation to expose the local bridge as a loopback
port on the remote daemon host:

```bash
ssh -N -R 127.0.0.1:9090:127.0.0.1:9090 user@remote-host
```

For unattended operations, add `-o ExitOnForwardFailure=yes` and run it under
your normal service supervisor. On the remote host, configure shisad to call
the tunneled loopback endpoint:

```bash
export SHISAD_SIGNER_LEDGER_URL="http://127.0.0.1:9090/sign"
export SHISAD_SIGNER_LEDGER_BEARER_TOKEN="<same token value as the bridge>"
```

The `SHISAD_SIGNER_LEDGER_URL` value includes `/sign` because the daemon sends
approval requests directly to the bridge signing endpoint.

### Private Network

If you use a VPN or private service network instead of SSH, keep the bridge
address private, restrict who can reach it, and protect the bearer token in
transit. The reference bridge binds to `127.0.0.1`; expose it to the private
network only through a controlled local proxy or tunnel. The daemon-side
configuration is the same shape:

```bash
export SHISAD_SIGNER_LEDGER_URL="https://ledger-bridge.private.example/sign"
export SHISAD_SIGNER_LEDGER_BEARER_TOKEN="..."
```

## Extract and Register the Public Key

The safest public-key extraction path runs locally and asks the Ledger to show
the address for review:

```bash
cd contrib/ledger-bridge
npm run --silent extract-key -- > ledger-pubkey.pem
```

Copy `ledger-pubkey.pem` to the remote daemon host over your normal secure
operator channel, then register it:

```bash
shisad signer register \
  --backend ledger \
  --user alice \
  --key-id ledger:stax-1 \
  --public-key ledger-pubkey.pem
```

The `ledger` backend defaults to ECDSA secp256k1 and the EIP-712 signing
scheme. If you use a non-default derivation path, use the same
`--derivation-path` value for `src/extract-key.ts` and `src/server.ts`:

```bash
npm run --silent extract-key -- --derivation-path "44'/60'/0'/0/0" > ledger-pubkey.pem
```

Run `npm install` first so `tsx` resolves from the bridge package's local
dependencies. Avoid redirecting `npx tsx ...` directly into a PEM file;
interactive package-manager prompts can corrupt the public-key export.

## Health and Readiness Checks

From the local workstation, check that the bridge is reachable and the token
matches:

```bash
curl -fsS \
  -H "Authorization: Bearer ${SHISAD_LEDGER_BRIDGE_BEARER_TOKEN}" \
  http://127.0.0.1:9090/extract-key >/tmp/ledger-extract-key.json
```

This endpoint contacts the Ledger and returns JSON containing
`public_key_pem`, `address`, and `derivation_path`. A configured token mismatch
returns HTTP 401.

From the remote daemon host, check the tunneled path:

```bash
curl -fsS \
  -H "Authorization: Bearer ${SHISAD_SIGNER_LEDGER_BEARER_TOKEN}" \
  http://127.0.0.1:9090/extract-key >/tmp/ledger-extract-key.remote.json
```

Then confirm the daemon has the signer key registered:

```bash
shisad signer list --backend ledger
```

The signer list confirms registration only. It does not prove the tunnel is up
or that the Ledger is unlocked; use the authenticated bridge reachability check
for that.

## Troubleshooting

### HTTP 401 from the Bridge

The daemon token and bridge token do not match, or the client omitted the
`Authorization: Bearer ...` header. Set the same value on both sides:

```bash
export SHISAD_LEDGER_BRIDGE_BEARER_TOKEN="..."
export SHISAD_SIGNER_LEDGER_BEARER_TOKEN="<same token value as the bridge>"
```

### Connection Refused or Timeout

The bridge is not running, the SSH tunnel is down, or the remote daemon is
using the wrong host/port. Confirm the bridge process is listening locally,
then restart the tunnel with `-o ExitOnForwardFailure=yes` so failed forwards
exit instead of silently continuing.

### Device Not Found, Hangs, or USB Permission Errors

Check that the Ledger is connected over USB HID, unlocked, and running the
Ethereum app. On Linux, install the appropriate udev rules for Ledger devices
and reconnect the device after rule changes. The reference bridge includes a
Linux HID interface filter for Nano devices, but host USB permissions still
need to allow the current user to access the device.

### Registered Key Does Not Verify

Re-extract the public key with the same derivation path used by the bridge and
re-register it under the intended key ID. The daemon verifies returned
signatures against the registered public key and fails closed when the key,
algorithm, or signing scheme does not match.

### L4 Policy Still Does Not Satisfy

The Ledger model and app path determine the review surface the bridge reports.
Stax and Flex are reported as `trusted_device_display`; Nano and unknown
models are reported as `opaque_device` with blind signing detected, which
downgrades the approval below L4.

## Related Docs

- [2FA and approval factors](../2FA.md)
- [Environment variables](../ENV-VARS.md)
- [Ledger bridge reference](../../contrib/ledger-bridge/README.md)
