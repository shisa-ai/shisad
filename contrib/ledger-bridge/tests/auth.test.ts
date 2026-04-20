import { describe, it } from "node:test";
import assert from "node:assert/strict";

import { isAuthorized } from "../src/auth";

describe("bridge bearer-token authorization", () => {
  it("allows requests when no bridge token is configured", () => {
    assert.equal(isAuthorized({}, ""), true);
  });

  it("requires an exact bearer token when configured", () => {
    assert.equal(
      isAuthorized({ authorization: "Bearer shared-secret" }, "shared-secret"),
      true,
    );
    assert.equal(isAuthorized({}, "shared-secret"), false);
    assert.equal(isAuthorized({ authorization: "Bearer wrong" }, "shared-secret"), false);
    assert.equal(isAuthorized({ authorization: "shared-secret" }, "shared-secret"), false);
  });
});
