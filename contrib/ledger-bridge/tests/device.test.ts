import { describe, it } from "node:test";
import assert from "node:assert/strict";

import { blindSignDetectedForModel, reviewSurfaceForModel } from "../src/device";

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
