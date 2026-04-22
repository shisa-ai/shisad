/**
 * Linux-only workaround: keep only the Ledger APDU HID interface.
 *
 * Some Ledger devices expose multiple HID interfaces (APDU + FIDO/U2F + sometimes
 * a generic keyboard interface). DMK's Node HID transport filters to the
 * APDU interface (`usagePage === 0xFFA0`) on darwin and win32, but not on
 * linux — so on linux DMK can latch onto the FIDO interface and the first
 * outbound APDU (GET_APP_AND_VERSION, `b0 01 00 00 00`) never completes.
 *
 * Upstream: https://github.com/LedgerHQ/device-sdk-ts/pull/1399 (darwin/win32
 * only). We apply the same gate on linux by wrapping node-hid's
 * `devicesAsync` before DMK ever calls it.
 *
 * node-hid populates `usagePage` on linux from kernel 2.6.x onward (every
 * kernel we reasonably target) and since node-hid 2.x. If a very old build
 * returns `usagePage: 0`, we fall through unchanged and log once — the
 * result is status-quo DMK behavior, not a regression.
 *
 * Import this module once, before any code that triggers
 * `require("node-hid")`. It is a side-effect-only module.
 */
import { createRequire } from "module";

const LEDGER_VENDOR_ID = 0x2c97;
const LEDGER_APDU_USAGE_PAGE = 0xffa0;

interface HidDeviceDescriptor {
  vendorId: number;
  productId: number;
  path?: string;
  interface?: number;
  usagePage?: number;
}

type DevicesAsync = (...args: unknown[]) => Promise<HidDeviceDescriptor[]>;

if (process.platform === "linux") {
  const req = createRequire(import.meta.url);
  const nodeHid = req("node-hid") as { devicesAsync: DevicesAsync };
  const original = nodeHid.devicesAsync.bind(nodeHid);

  let warnedMissingUsagePage = false;

  nodeHid.devicesAsync = async (...args: unknown[]) => {
    const all = await original(...args);
    return all.filter((d) => {
      if (d.vendorId !== LEDGER_VENDOR_ID) return true;
      if (d.usagePage === undefined || d.usagePage === 0) {
        if (!warnedMissingUsagePage) {
          warnedMissingUsagePage = true;
          process.stderr.write(
            "[ledger-bridge] node-hid returned no usagePage for a Ledger interface on linux; " +
              "skipping APDU-interface filter (upgrade node-hid to >=2.x if you hit APDU hangs).\n",
          );
        }
        return true;
      }
      return d.usagePage === LEDGER_APDU_USAGE_PAGE;
    });
  };
}
