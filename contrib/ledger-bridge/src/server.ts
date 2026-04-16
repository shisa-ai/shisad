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
import { hexToBytes, uncompressedSecp256k1ToPem } from "./crypto-utils";

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
// Extract public key handler
// ---------------------------------------------------------------------------

interface ExtractKeyResponse {
  ok: boolean;
  public_key_pem: string;
  address: string;
  derivation_path: string;
  error: string;
}

async function handleExtractKey(): Promise<ExtractKeyResponse> {
  const dmk = getDmk();
  const device = await connectDevice(dmk);
  await waitForUnlock(dmk, device.sessionId);
  const signerEth = buildEthSigner(dmk, device.sessionId);

  try {
    const { observable } = signerEth.getAddress(DERIVATION_PATH, {
      checkOnDevice: false,
    });

    const output = await firstValueFrom(
      observable.pipe(
        filter((state: any) => {
          if (state.status === DeviceActionStatus.Pending) {
            const interaction = state.intermediateValue.requiredUserInteraction;
            if (interaction) printDeviceInteraction(interaction);
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

    const pem = uncompressedSecp256k1ToPem(output.publicKey);
    return {
      ok: true,
      public_key_pem: pem,
      address: output.address,
      derivation_path: DERIVATION_PATH,
      error: "",
    };
  } finally {
    await dmk.disconnect({ sessionId: device.sessionId }).catch(() => {});
  }
}

// ---------------------------------------------------------------------------
// HTTP server
// ---------------------------------------------------------------------------

const MAX_BODY_BYTES = 1024 * 1024; // 1 MB

function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    req.on("data", (chunk: Buffer) => {
      total += chunk.length;
      if (total > MAX_BODY_BYTES) { req.destroy(); reject(new Error("body_too_large")); return; }
      chunks.push(chunk);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

function sendJson(res: ServerResponse, status: number, payload: object): void {
  const encoded = JSON.stringify(payload);
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Content-Length": Buffer.byteLength(encoded).toString(),
  });
  res.end(encoded);
}

const server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
  // GET /extract-key — extract public key from connected Ledger
  if (req.url?.startsWith("/extract-key")) {
    try {
      const response = await handleExtractKey();
      sendJson(res, 200, response);
    } catch (err) {
      sendJson(res, 500, { ok: false, public_key_pem: "", address: "", derivation_path: "", error: (err as Error)?.message ?? "extract_key_failed" });
    }
    return;
  }

  // POST /sign — sign an intent envelope
  if (req.method === "POST" && req.url?.startsWith("/sign")) {
    try {
      const body = await readBody(req);
      const payload: SignRequest = JSON.parse(body.toString("utf-8"));
      const response = await handleSignRequest(payload);
      sendJson(res, 200, response);
    } catch (err) {
      sendJson(res, 500, {
        status: "error", signer_key_id: "", signature: "", signed_at: "",
        review_surface: "", blind_sign_detected: false,
        reason: (err as Error)?.message ?? "internal_bridge_error",
      });
    }
    return;
  }

  sendJson(res, 404, { error: "not_found" });
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
