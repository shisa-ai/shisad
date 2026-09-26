import { APPLICATION_ORIGIN_TOKEN } from "../src/generated/origin-token";
import { describe, it, mock } from "node:test";
import assert from "node:assert/strict";
import { SignerEthBuilder } from "@ledgerhq/device-signer-kit-ethereum";

import { blindSignDetectedForModel, reviewSurfaceForModel, buildEthSigner } from "../src/device";

describe("Ledger model review-surface mapping", () => {
  it("treats Stax and Flex as trusted-display devices", () => {
    for (const model of ["stax", "europa", "Ledger Stax", "flex", "Ledger Flex"]) {
      assert.equal(reviewSurfaceForModel(model), "trusted_device_display");
      assert.equal(blindSignDetectedForModel(model), false);
    }
  });

  it("fails closed for Nano and unknown models", () => {
    for (const model of ["nanoS", "nanoSP", "nanoX", "unknown", ""]) {
      assert.equal(reviewSurfaceForModel(model), "opaque_device");
      assert.equal(blindSignDetectedForModel(model), true);
    }
  });
});


it("forwards the configured origin token to the Ledger SDK", async () => {
  const previous = process.env.SHISAD_LEDGER_ORIGIN_TOKEN;
  const tokens: unknown[] = [];
  // Inspect the SDK builder before it constructs a device/context module.
  const stub = mock.method(SignerEthBuilder.prototype, "build", function (this: { _originToken?: string }) {
    tokens.push(this._originToken);
    return {};
  });
  try {
    process.env.SHISAD_LEDGER_ORIGIN_TOKEN = " test-origin ";
    buildEthSigner({} as never, "session-1");
    delete process.env.SHISAD_LEDGER_ORIGIN_TOKEN;
    buildEthSigner({} as never, "session-1");
    assert.equal(tokens[0], "test-origin");
    assert.ok(Boolean(APPLICATION_ORIGIN_TOKEN) && tokens[1] === APPLICATION_ORIGIN_TOKEN, "Built-in token must reach SDK when runtime override is absent");
  } finally {
    stub.mock.restore();
    if (previous === undefined) delete process.env.SHISAD_LEDGER_ORIGIN_TOKEN;
    else process.env.SHISAD_LEDGER_ORIGIN_TOKEN = previous;
  }
});
