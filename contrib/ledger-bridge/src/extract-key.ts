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
import { uncompressedSecp256k1ToPem } from "./crypto-utils";

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

// uncompressedSecp256k1ToPem and hexToBytes are in crypto-utils.ts

main().catch((err) => {
  process.stderr.write(`Error: ${(err as Error).message}\n`);
  process.exit(1);
});
