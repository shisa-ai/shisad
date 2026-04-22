/**
 * Ledger DMK device connection management.
 *
 * Maintains a persistent device session that is reused across sign requests.
 * Automatically reconnects if the device disconnects or the session becomes
 * stale. This avoids the 200-500ms USB enumeration cost per request.
 */

// Must run before the DMK transport is imported so node-hid is patched in
// its CJS module cache before DMK requires it.
import "./linux-hid-filter.js";

import {
  type DeviceManagementKit,
  DeviceManagementKitBuilder,
  ConsoleLogger,
  DeviceStatus,
} from "@ledgerhq/device-management-kit";
import { nodeHidTransportFactory } from "@ledgerhq/device-transport-kit-node-hid";
import { SignerEthBuilder, type SignerEth } from "@ledgerhq/device-signer-kit-ethereum";
import { firstValueFrom, filter, take, timeout } from "rxjs";

const CONNECT_TIMEOUT_MS = 60_000;

let dmkInstance: DeviceManagementKit | null = null;

export function getDmk(): DeviceManagementKit {
  if (!dmkInstance) {
    dmkInstance = new DeviceManagementKitBuilder()
      .addLogger(new ConsoleLogger())
      .addTransport(nodeHidTransportFactory)
      .build();
  }
  return dmkInstance;
}

export interface ConnectedDevice {
  sessionId: string;
  model: string;
}

// ---------------------------------------------------------------------------
// Persistent session management
// ---------------------------------------------------------------------------

let cachedSession: { sessionId: string; model: string; signerEth: SignerEth } | null = null;

/**
 * Get an active device session, reusing the existing one if still connected.
 * Reconnects automatically if the device was disconnected or unplugged.
 */
export async function getOrConnectDevice(
  dmk: DeviceManagementKit,
): Promise<{ sessionId: string; model: string; signerEth: SignerEth }> {
  // Check if cached session is still alive
  if (cachedSession) {
    try {
      const state = await firstValueFrom(
        dmk.getDeviceSessionState({ sessionId: cachedSession.sessionId }).pipe(
          take(1),
          timeout(3_000),
        ),
      );
      if (state.deviceStatus !== DeviceStatus.NOT_CONNECTED) {
        // Session is alive — check if locked
        if (state.deviceStatus === DeviceStatus.LOCKED) {
          process.stderr.write("Device is locked. Enter your PIN...\n");
          await firstValueFrom(
            dmk.getDeviceSessionState({ sessionId: cachedSession.sessionId }).pipe(
              filter((s) => s.deviceStatus !== DeviceStatus.LOCKED),
              take(1),
              timeout(CONNECT_TIMEOUT_MS),
            ),
          );
          process.stderr.write("Device unlocked.\n");
        }
        return cachedSession;
      }
    } catch {
      // Session is stale — fall through to reconnect
    }
    process.stderr.write("Device session lost, reconnecting...\n");
    cachedSession = null;
  }

  // Fresh connection
  const device = await connectDevice(dmk);
  await waitForUnlock(dmk, device.sessionId);
  const signerEth = buildEthSigner(dmk, device.sessionId);
  cachedSession = { ...device, signerEth };
  return cachedSession;
}

/**
 * Invalidate the cached session (e.g., after a device error).
 */
export function invalidateSession(): void {
  if (cachedSession) {
    const { sessionId } = cachedSession;
    cachedSession = null;
    const dmk = getDmk();
    dmk.disconnect({ sessionId }).catch(() => {});
  }
}

// ---------------------------------------------------------------------------
// Low-level connection helpers (used by getOrConnectDevice and extract-key)
// ---------------------------------------------------------------------------

/**
 * Wait for a Ledger device to appear and connect to it.
 */
export async function connectDevice(
  dmk: DeviceManagementKit,
): Promise<ConnectedDevice> {
  process.stderr.write("Waiting for Ledger device (plug in via USB)...\n");

  const devices = await firstValueFrom(
    dmk.listenToAvailableDevices({}).pipe(
      filter((list) => list.length > 0),
      timeout(CONNECT_TIMEOUT_MS),
    ),
  );

  const device = devices[0]!;
  const sessionId = await dmk.connect({ device });
  const model = device.deviceModel?.model ?? "unknown";

  process.stderr.write(
    `Connected to ${model} (session: ${sessionId.slice(0, 8)}...)\n`,
  );

  return { sessionId, model };
}

/**
 * Wait for the device to be unlocked if it's currently PIN-locked.
 */
export async function waitForUnlock(
  dmk: DeviceManagementKit,
  sessionId: string,
): Promise<void> {
  const state = await firstValueFrom(
    dmk.getDeviceSessionState({ sessionId }).pipe(take(1)),
  );

  if (state.deviceStatus === DeviceStatus.LOCKED) {
    process.stderr.write("Device is locked. Enter your PIN...\n");
    await firstValueFrom(
      dmk.getDeviceSessionState({ sessionId }).pipe(
        filter((s) => s.deviceStatus !== DeviceStatus.LOCKED),
        take(1),
        timeout(CONNECT_TIMEOUT_MS),
      ),
    );
    process.stderr.write("Device unlocked.\n");
  }
}

/**
 * Build an Ethereum signer for the connected session.
 */
export function buildEthSigner(
  dmk: DeviceManagementKit,
  sessionId: string,
): SignerEth {
  return new SignerEthBuilder({ dmk, sessionId }).build();
}

/**
 * Map device model to a shisad review_surface value.
 */
export function reviewSurfaceForModel(model: string): string {
  const normalized = model.trim().toLowerCase();
  if (
    normalized === "stax" ||
    normalized === "ledger stax" ||
    normalized === "europa" ||
    normalized === "flex" ||
    normalized === "ledger flex"
  ) {
    return "trusted_device_display";
  }
  return "opaque_device";
}

export function blindSignDetectedForModel(model: string): boolean {
  return reviewSurfaceForModel(model) !== "trusted_device_display";
}
