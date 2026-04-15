/**
 * Extract a secp256k1 public key from a connected Ledger device and output
 * it in PEM format for use with `shisad signer register`.
 *
 * Usage:
 *   npx tsx src/extract-key.ts [--derivation-path "44'/60'/0'/0/0"]
 *
 * The PEM-encoded public key is written to stdout.  Device prompts and
 * status messages go to stderr.
 */

import { DeviceActionStatus, UserInteractionRequired } from "@ledgerhq/device-management-kit";
import { firstValueFrom, filter, map } from "rxjs";
import { getDmk, connectDevice, waitForUnlock, buildEthSigner } from "./device";

const DERIVATION_PATH =
  process.argv.find((_, i, a) => a[i - 1] === "--derivation-path") ?? "44'/60'/0'/0/0";

async function main(): Promise<void> {
  const dmk = getDmk();
  const device = await connectDevice(dmk);
  await waitForUnlock(dmk, device.sessionId);

  const signerEth = buildEthSigner(dmk, device.sessionId);

  process.stderr.write(`Extracting public key at ${DERIVATION_PATH}...\n`);
  process.stderr.write("Verify the address on your Ledger screen if prompted.\n");

  const { observable } = signerEth.getAddress(DERIVATION_PATH, {
    checkOnDevice: true,
  });

  const output = await firstValueFrom(
    observable.pipe(
      filter((state: any) => {
        if (state.status === DeviceActionStatus.Pending) {
          const interaction = state.intermediateValue.requiredUserInteraction;
          if (interaction === UserInteractionRequired.ConfirmOpenApp) {
            process.stderr.write("Confirm opening the Ethereum app on your Ledger...\n");
          } else if (interaction === UserInteractionRequired.VerifyAddress) {
            process.stderr.write("Verify the address on your Ledger screen...\n");
          }
        }
        return (
          state.status === DeviceActionStatus.Completed ||
          state.status === DeviceActionStatus.Error
        );
      }),
      map((state: any) => {
        if (state.status === DeviceActionStatus.Error) throw state.error;
        return state.output as { address: string; publicKey: string };
      }),
    ),
  );

  process.stderr.write(`Address: ${output.address}\n`);

  // Convert uncompressed public key hex to PEM (SubjectPublicKeyInfo).
  const pubKeyHex = output.publicKey.replace(/^0x/, "");
  const pem = uncompressedSecp256k1ToPem(pubKeyHex);

  // Write PEM to stdout for piping.
  process.stdout.write(pem);

  await dmk.disconnect({ sessionId: device.sessionId }).catch(() => {});
  process.stderr.write("Done.\n");
}

/**
 * Wrap an uncompressed secp256k1 public key (04 + 64 bytes) in a
 * SubjectPublicKeyInfo DER structure and encode as PEM.
 *
 * The OID for id-ecPublicKey is 1.2.840.10045.2.1, and the named curve
 * OID for secp256k1 is 1.3.132.0.10.
 */
function uncompressedSecp256k1ToPem(pubKeyHex: string): string {
  // Ensure leading 04 (uncompressed point).
  if (!pubKeyHex.startsWith("04") && pubKeyHex.length === 128) {
    pubKeyHex = "04" + pubKeyHex;
  }
  const pubKeyBytes = hexToBytes(pubKeyHex);

  // ASN.1 header for secp256k1 SubjectPublicKeyInfo:
  //   SEQUENCE {
  //     SEQUENCE { OID ecPublicKey, OID secp256k1 }
  //     BIT STRING (0x00 padding + uncompressed point)
  //   }
  const header = hexToBytes(
    "3056301006072a8648ce3d020106052b8104000a034200",
  );
  const der = new Uint8Array(header.length + pubKeyBytes.length);
  der.set(header);
  der.set(pubKeyBytes, header.length);

  const b64 = Buffer.from(der).toString("base64");
  const lines = b64.match(/.{1,64}/g) ?? [];
  return `-----BEGIN PUBLIC KEY-----\n${lines.join("\n")}\n-----END PUBLIC KEY-----\n`;
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
}

main().catch((err) => {
  process.stderr.write(`Error: ${(err as Error).message}\n`);
  process.exit(1);
});
