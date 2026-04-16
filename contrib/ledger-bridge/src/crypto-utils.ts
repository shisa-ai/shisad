/**
 * Shared crypto utilities for the Ledger bridge.
 */

export function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
}

/**
 * Wrap an uncompressed secp256k1 public key (04 + 64 bytes) in a
 * SubjectPublicKeyInfo DER structure and encode as PEM.
 *
 * OID id-ecPublicKey: 1.2.840.10045.2.1
 * OID secp256k1: 1.3.132.0.10
 */
export function uncompressedSecp256k1ToPem(pubKeyHex: string): string {
  let hex = pubKeyHex.replace(/^0x/, "");
  if (!hex.startsWith("04") && hex.length === 128) hex = "04" + hex;
  const pubKeyBytes = hexToBytes(hex);
  const header = hexToBytes("3056301006072a8648ce3d020106052b8104000a034200");
  const der = new Uint8Array(header.length + pubKeyBytes.length);
  der.set(header);
  der.set(pubKeyBytes, header.length);
  const b64 = Buffer.from(der).toString("base64");
  const lines = b64.match(/.{1,64}/g) ?? [];
  return `-----BEGIN PUBLIC KEY-----\n${lines.join("\n")}\n-----END PUBLIC KEY-----\n`;
}
