/**
 * shisad Ledger bridge — HTTP signing server.
 *
 * Implements the same sign-request/response contract as the shisad KMS
 * backend.  Receives an IntentEnvelope from the shisad daemon, builds
 * an EIP-712 typed-data payload, pushes it to a connected Ledger device
 * via DMK's Ethereum signTypedData, and returns the signature.
 * The device renders structured labeled fields with Clear Signing support.
 *
 * Usage:
 *   npx tsx src/server.ts [--port 9090] [--derivation-path "44'/60'/0'/0/0"]
 */

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { DeviceActionStatus, UserInteractionRequired } from "@ledgerhq/device-management-kit";
import { firstValueFrom, filter, map } from "rxjs";

import { getDmk, connectDevice, waitForUnlock, buildEthSigner, reviewSurfaceForModel } from "./device";
import { buildTypedData, formatForDevice, type IntentEnvelope } from "./format";

// ---------------------------------------------------------------------------
// CLI args
// ---------------------------------------------------------------------------
const PORT = parseInt(process.argv.find((_, i, a) => a[i - 1] === "--port") ?? "9090", 10);
const DERIVATION_PATH = process.argv.find((_, i, a) => a[i - 1] === "--derivation-path") ?? "44'/60'/0'/0/0";

// ---------------------------------------------------------------------------
// Sign request handler
// ---------------------------------------------------------------------------

interface SignRequest {
  schema_version: string;
  backend: string;
  signer_key_id: string;
  intent_envelope_hash: string;
  intent_envelope: IntentEnvelope;
  timeout_seconds: number;
}

interface SignResponse {
  status: "approved" | "rejected" | "expired" | "error";
  signer_key_id: string;
  signature: string;
  signed_at: string;
  review_surface: string;
  blind_sign_detected: boolean;
  reason: string;
}

function printDeviceInteraction(interaction: string): void {
  const messages: Record<string, string> = {
    [UserInteractionRequired.UnlockDevice]: "Enter your PIN on the Ledger...",
    [UserInteractionRequired.ConfirmOpenApp]: "Confirm opening the app on your Ledger...",
    [UserInteractionRequired.SignPersonalMessage]: "Review and sign the message on your Ledger...",
    [UserInteractionRequired.SignTypedData]: "Review and sign the typed data on your Ledger...",
  };
  const msg = messages[interaction];
  if (msg) process.stderr.write(`  ${msg}\n`);
}

async function handleSignRequest(req: SignRequest): Promise<SignResponse> {
  const dmk = getDmk();

  // Connect and prepare device.
  const device = await connectDevice(dmk);
  await waitForUnlock(dmk, device.sessionId);
  const signerEth = buildEthSigner(dmk, device.sessionId);

  // Build EIP-712 typed data for structured device display.
  const typedData = buildTypedData(req.intent_envelope);
  const displayMessage = formatForDevice(req.intent_envelope);
  process.stderr.write(`\nSigning (EIP-712):\n${displayMessage}\n\n`);

  try {
    // Sign via EIP-712 signTypedData — device renders structured labeled
    // fields on its trusted display and the user confirms with physical touch.
    const { observable, cancel } = signerEth.signTypedData(
      DERIVATION_PATH,
      typedData,
    );

    const output = await firstValueFrom(
      observable.pipe(
        filter((state: any) => {
          if (state.status === DeviceActionStatus.Pending) {
            printDeviceInteraction(
              state.intermediateValue.requiredUserInteraction,
            );
          }
          return (
            state.status === DeviceActionStatus.Completed ||
            state.status === DeviceActionStatus.Error
          );
        }),
        map((state: any) => {
          if (state.status === DeviceActionStatus.Error) {
            throw state.error;
          }
          return state.output as { r: string; s: string; v: number };
        }),
      ),
    );

    // Encode (r, s) as a DER-encoded ECDSA signature in base64.
    // The Python side expects "base64:<DER-encoded>".
    const rBytes = hexToBytes(output.r.replace(/^0x/, ""));
    const sBytes = hexToBytes(output.s.replace(/^0x/, ""));
    const derSignature = encodeDerSignature(rBytes, sBytes);
    const signatureB64 = "base64:" + Buffer.from(derSignature).toString("base64");

    return {
      status: "approved",
      signer_key_id: req.signer_key_id,
      signature: signatureB64,
      signed_at: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
      review_surface: reviewSurfaceForModel(device.model),
      blind_sign_detected: false,
      reason: "",
    };
  } catch (err: unknown) {
    const tag = (err as any)?._tag ?? "";
    if (tag === "RefusedByUserDAError") {
      return {
        status: "rejected",
        signer_key_id: req.signer_key_id,
        signature: "",
        signed_at: "",
        review_surface: reviewSurfaceForModel(device.model),
        blind_sign_detected: false,
        reason: "user_rejected_on_device",
      };
    }
    return {
      status: "error",
      signer_key_id: req.signer_key_id,
      signature: "",
      signed_at: "",
      review_surface: "",
      blind_sign_detected: false,
      reason: (err as Error)?.message ?? "unknown_device_error",
    };
  } finally {
    await dmk.disconnect({ sessionId: device.sessionId }).catch(() => {});
  }
}

// ---------------------------------------------------------------------------
// DER encoding helpers
// ---------------------------------------------------------------------------

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
}

function encodeDerInteger(value: Uint8Array): Uint8Array {
  // Strip leading zeros but keep one if the high bit is set.
  let start = 0;
  while (start < value.length - 1 && value[start] === 0) start++;
  let trimmed = value.slice(start);
  // Prepend 0x00 if high bit is set (positive integer encoding).
  if (trimmed[0]! & 0x80) {
    const padded = new Uint8Array(trimmed.length + 1);
    padded[0] = 0;
    padded.set(trimmed, 1);
    trimmed = padded;
  }
  const result = new Uint8Array(2 + trimmed.length);
  result[0] = 0x02; // INTEGER tag
  result[1] = trimmed.length;
  result.set(trimmed, 2);
  return result;
}

function encodeDerSignature(r: Uint8Array, s: Uint8Array): Uint8Array {
  const rDer = encodeDerInteger(r);
  const sDer = encodeDerInteger(s);
  const seq = new Uint8Array(2 + rDer.length + sDer.length);
  seq[0] = 0x30; // SEQUENCE tag
  seq[1] = rDer.length + sDer.length;
  seq.set(rDer, 2);
  seq.set(sDer, 2 + rDer.length);
  return seq;
}

// ---------------------------------------------------------------------------
// HTTP server
// ---------------------------------------------------------------------------

function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

const server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
  if (req.method !== "POST" || !req.url?.startsWith("/sign")) {
    res.writeHead(404, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "not_found" }));
    return;
  }

  try {
    const body = await readBody(req);
    const payload: SignRequest = JSON.parse(body.toString("utf-8"));
    const response = await handleSignRequest(payload);
    const encoded = JSON.stringify(response);
    res.writeHead(200, {
      "Content-Type": "application/json",
      "Content-Length": Buffer.byteLength(encoded).toString(),
    });
    res.end(encoded);
  } catch (err) {
    const errResponse: SignResponse = {
      status: "error",
      signer_key_id: "",
      signature: "",
      signed_at: "",
      review_surface: "",
      blind_sign_detected: false,
      reason: (err as Error)?.message ?? "internal_bridge_error",
    };
    const encoded = JSON.stringify(errResponse);
    res.writeHead(500, {
      "Content-Type": "application/json",
      "Content-Length": Buffer.byteLength(encoded).toString(),
    });
    res.end(encoded);
  }
});

server.on("error", (err: NodeJS.ErrnoException) => {
  if (err.code === "EADDRINUSE") {
    process.stderr.write(
      `Error: port ${PORT} is already in use.\n` +
      `Kill the existing process or use --port <other-port>.\n`,
    );
  } else {
    process.stderr.write(`Server error: ${err.message}\n`);
  }
  process.exit(1);
});

server.listen(PORT, "127.0.0.1", () => {
  process.stderr.write(
    `shisad-ledger-bridge listening on http://127.0.0.1:${PORT}/sign\n` +
    `Derivation path: ${DERIVATION_PATH}\n`,
  );
});

// Graceful shutdown.
process.on("SIGINT", () => {
  server.close();
  process.exit(0);
});
process.on("SIGTERM", () => {
  server.close();
  process.exit(0);
});
