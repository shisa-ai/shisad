/**
 * Ledger DMK device connection and model detection helpers.
 */

import {
  type DeviceManagementKit,
  DeviceManagementKitBuilder,
  ConsoleLogger,
  DeviceStatus,
  DeviceSessionStateType,
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
  hasLargeScreen: boolean;
}

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
  const hasLargeScreen = /stax|flex/i.test(model);

  process.stderr.write(
    `Connected to ${model} (session: ${sessionId.slice(0, 8)}...)\n`,
  );

  return { sessionId, model, hasLargeScreen };
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
 * All Ledger devices with screens report trusted_device_display.
 */
export function reviewSurfaceForModel(model: string): string {
  return "trusted_device_display";
}
